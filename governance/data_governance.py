"""Data governance: least-privilege connections, catalog-driven classification, PII masking.

Enforcement happens at two independent layers:
  1. Postgres: each agent connects as its own role with table/column-level grants,
     so the database itself refuses anything outside the agent's mandate.
  2. Application: every column a tool returns is looked up in gov.data_catalog;
     'pii' is masked unless OPA grants read_pii, 'restricted' is always removed.
"""
from __future__ import annotations

import time
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from .config import settings

AGENT_DB_ROLE = {"order": "agent_order", "billing": "agent_billing", "admin": "agent_admin"}

_catalog_cache: dict = {"at": 0.0, "data": {}}


@contextmanager
def agent_connection(agent: str):
    role = AGENT_DB_ROLE[agent]
    with psycopg.connect(settings.dsn(role), row_factory=dict_row, connect_timeout=5) as conn:
        yield conn


def reader_connection():
    return psycopg.connect(settings.dsn("gov_reader"), row_factory=dict_row, connect_timeout=5)


def catalog() -> dict[tuple[str, str, str], str]:
    if time.time() - _catalog_cache["at"] > 60:
        with reader_connection() as c:
            rows = c.execute("SELECT schema_name, table_name, column_name, classification FROM gov.data_catalog").fetchall()
        _catalog_cache.update(at=time.time(), data={(r["schema_name"], r["table_name"], r["column_name"]): r["classification"] for r in rows})
    return _catalog_cache["data"]


def mask_value(column: str, value):
    if value is None:
        return None
    s = str(value)
    if "email" in column and "@" in s:
        local, domain = s.split("@", 1)
        return f"{local[0]}***@{domain}"
    if "phone" in column:
        return "*" * max(len(s) - 4, 0) + s[-4:]
    if "name" in column:
        parts = s.split()
        return " ".join(p[0] + "." for p in parts)
    if "card" in column:
        return "****"
    return "***"


def govern_rows(rows: list[dict], source: dict[str, tuple[str, str, str]], pii_allowed: bool) -> tuple[list[dict], dict]:
    """Apply catalog classifications to tool output. `source` maps result key -> (schema, table, column)."""
    cat = catalog()
    masked, removed, unclassified = set(), set(), set()
    out = []
    for row in rows:
        new = {}
        for k, v in row.items():
            cls = cat.get(source.get(k, ("", "", "")))
            if k in source and cls is None:
                unclassified.add(k)
            if cls == "restricted":
                removed.add(k)
                continue
            if cls == "pii" and not pii_allowed:
                masked.add(k)
                v = mask_value(k, v)
            new[k] = v
        out.append(new)
    return out, {"masked": sorted(masked), "removed": sorted(removed), "unclassified": sorted(unclassified),
                 "pii_allowed": pii_allowed}


def privilege_matrix() -> list[dict]:
    """Effective table privileges for every governed role (evidence for audits)."""
    roles = list(AGENT_DB_ROLE.values()) + ["gov_audit_writer", "gov_reader"]
    sql = """
      SELECT r.rolname AS role, n.nspname || '.' || c.relname AS object,
             has_table_privilege(r.oid, c.oid, 'SELECT') AS sel,
             has_table_privilege(r.oid, c.oid, 'INSERT') AS ins,
             has_table_privilege(r.oid, c.oid, 'UPDATE') AS upd,
             has_table_privilege(r.oid, c.oid, 'DELETE') AS del,
             (SELECT array_agg(a.attname ORDER BY a.attnum) FROM pg_attribute a
               WHERE a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped
                 AND has_column_privilege(r.oid, c.oid, a.attnum, 'SELECT')) AS readable_columns
      FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE r.rolname = ANY(%s) AND c.relkind = 'r' AND n.nspname IN ('sales','billing','iam','gov')
      ORDER BY 1, 2"""
    with psycopg.connect(settings.dsn(), row_factory=dict_row, connect_timeout=5) as c:
        return [r for r in c.execute(sql, (roles,)).fetchall()
                if r["sel"] or r["ins"] or r["upd"] or r["del"] or r["readable_columns"]]


def healthy() -> bool:
    try:
        with reader_connection() as c:
            c.execute("SELECT 1")
        return True
    except Exception:  # noqa: BLE001
        return False
