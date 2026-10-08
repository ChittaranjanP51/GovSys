"""Operations governance: tamper-evident audit trail + tracing.

Every request (allowed or blocked) is written:
  * to Postgres gov.audit_log as the INSERT-only role gov_audit_writer, hash-chained
    (row_hash = sha256(prev_hash + canonical record)); UPDATE/DELETE/TRUNCATE are
    rejected by triggers.
  * to logs/audit.jsonl (local, line-delimited copy for SIEM shipping).
  * to Langfuse as a trace with one span per governance check (when configured).
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

from .config import settings

GENESIS = "0" * 64
_LOCK = threading.Lock()
AUDIT_JSONL = settings.logs_dir / "audit.jsonl"


def _canonical(rec: dict) -> str:
    return json.dumps(rec, sort_keys=True, default=str, separators=(",", ":"))


def row_digest(prev_hash: str, rec: dict) -> str:
    return hashlib.sha256((prev_hash + _canonical(rec)).encode()).hexdigest()


HASHED_FIELDS = ["request_id", "username", "roles", "agent_path", "final_decision", "blocked_at",
                 "checks", "tool_calls", "model", "prompt_redacted", "response_redacted", "latency_ms"]


def write(record: dict) -> dict:
    rec = {k: record.get(k) for k in HASHED_FIELDS}
    rec["request_id"] = str(rec["request_id"])
    with _LOCK, psycopg.connect(settings.dsn("gov_audit_writer"), row_factory=dict_row, connect_timeout=5) as c:
        with c.transaction():
            c.execute("SELECT pg_advisory_xact_lock(424242)")
            tip = c.execute("SELECT row_hash FROM gov.audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = tip["row_hash"] if tip else GENESIS
            h = row_digest(prev, rec)
            row = c.execute(
                """INSERT INTO gov.audit_log (request_id, username, roles, agent_path, final_decision,
                     blocked_at, checks, tool_calls, model, prompt_redacted, response_redacted,
                     latency_ms, prev_hash, row_hash)
                   VALUES (%(request_id)s, %(username)s, %(roles)s, %(agent_path)s, %(final_decision)s,
                     %(blocked_at)s, %(checks)s, %(tool_calls)s, %(model)s, %(prompt_redacted)s,
                     %(response_redacted)s, %(latency_ms)s, %(prev)s, %(h)s) RETURNING id""",
                rec | {"checks": Jsonb(rec["checks"]), "tool_calls": Jsonb(rec["tool_calls"]), "prev": prev, "h": h},
            ).fetchone()
    entry = rec | {"id": row["id"], "ts": datetime.now(timezone.utc).isoformat(), "prev_hash": prev, "row_hash": h}
    with open(AUDIT_JSONL, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, default=str) + "\n")
    _langfuse(entry)
    return entry


def read(limit: int | None = None) -> list[dict]:
    sql = "SELECT * FROM gov.audit_log ORDER BY id" + ("" if limit is None else " DESC LIMIT %s")
    with psycopg.connect(settings.dsn("gov_reader"), row_factory=dict_row, connect_timeout=5) as c:
        rows = c.execute(sql, () if limit is None else (limit,)).fetchall()
    return rows if limit is None else rows[::-1]


def verify_chain(rows: list[dict] | None = None) -> dict:
    rows = rows if rows is not None else read()
    prev = GENESIS
    for r in rows:
        rec = {k: r[k] for k in HASHED_FIELDS}
        rec["request_id"] = str(rec["request_id"])
        if r["prev_hash"] != prev or row_digest(prev, rec) != r["row_hash"]:
            return {"intact": False, "rows": len(rows), "broken_at_id": r["id"]}
        prev = r["row_hash"]
    return {"intact": True, "rows": len(rows), "tip": prev}


# ------------------------------------------------------------------ tracing
_lf = None


def langfuse_enabled() -> bool:
    return bool(settings.langfuse_host and settings.langfuse_public_key and settings.langfuse_secret_key)


def langfuse_healthy() -> bool:
    """Server reachable AND our API keys accepted (traces would otherwise be dropped)."""
    try:
        import httpx
        if httpx.get(f"{settings.langfuse_host}/api/public/health", timeout=3).status_code != 200:
            return False
        r = httpx.get(f"{settings.langfuse_host}/api/public/projects", timeout=3,
                      auth=(settings.langfuse_public_key, settings.langfuse_secret_key))
        return r.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def _langfuse(entry: dict) -> None:
    global _lf
    if not langfuse_enabled():
        return
    try:
        if _lf is None:
            from langfuse import Langfuse
            _lf = Langfuse(public_key=settings.langfuse_public_key, secret_key=settings.langfuse_secret_key,
                           host=settings.langfuse_host)
        # Langfuse v2 SDK: one trace per request, one span per governance check.
        trace = _lf.trace(id=entry["request_id"], name="govsys.request", user_id=entry["username"],
                          input=entry["prompt_redacted"], output=entry["response_redacted"],
                          tags=[entry["final_decision"]] + ([f"blocked:{entry['blocked_at']}"] if entry["blocked_at"] else []),
                          metadata={"agent_path": entry["agent_path"], "model": entry["model"],
                                    "audit_id": entry["id"], "row_hash": entry["row_hash"],
                                    "latency_ms": entry["latency_ms"]})
        for chk in entry["checks"]:
            trace.span(name=f"check.{chk['check']}", input=chk.get("evidence"),
                       output={"status": chk["status"], "detail": chk["detail"]},
                       level="ERROR" if chk["status"] == "fail" else "DEFAULT",
                       status_message=chk["detail"], metadata={"latency_ms": chk.get("latency_ms")})
        for call in entry["tool_calls"]:
            trace.event(name=f"tool.{call['tool']}", input=call.get("args"), output={"decision": call["decision"]})
        _lf.flush()
    except Exception:  # noqa: BLE001 - tracing must never break the request path
        pass
