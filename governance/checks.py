"""The seven runtime governance checks evaluated for every request."""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field

CHECKS = [
    ("identity", "Human identity", "Identity governance"),
    ("input_guardrails", "Input guardrails", "Runtime governance"),
    ("model_approval", "Model approval gate", "Model governance"),
    ("agent_authz", "Agent identity & handoff policy", "Identity + policy governance"),
    ("tool_authz", "Tool-call authorization", "Policy governance"),
    ("data_access", "Least-privilege data access & PII masking", "Data governance"),
    ("output_guardrails", "Output guardrails", "Runtime governance"),
]
CHECK_IDS = [c[0] for c in CHECKS]
CHECK_LABELS = {c[0]: c[1] for c in CHECKS}
CHECK_LAYERS = {c[0]: c[2] for c in CHECKS}

PASS, FAIL, SKIP = "pass", "fail", "skipped"


@dataclass
class CheckResult:
    check: str
    status: str                  # pass | fail
    detail: str
    evidence: dict = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


class Timer:
    def __init__(self) -> None:
        self.ms = 0.0


@contextmanager
def timed():
    t = Timer()
    start = time.perf_counter()
    try:
        yield t
    finally:
        t.ms = round((time.perf_counter() - start) * 1000, 2)


def summarize(results: list[dict]) -> dict[str, dict]:
    """Collapse a list of check results (a check may run several times, e.g. one
    tool_authz per tool call) into one status per check: any fail -> fail."""
    out: dict[str, dict] = {cid: {"status": SKIP, "detail": "not reached", "runs": 0} for cid in CHECK_IDS}
    for r in results:
        cur = out[r["check"]]
        cur["runs"] += 1
        if cur["status"] == SKIP or (r["status"] == FAIL and cur["status"] == PASS):
            cur["status"], cur["detail"] = r["status"], r["detail"]
        elif r["status"] == PASS and cur["status"] == PASS:
            cur["detail"] = r["detail"] if cur["runs"] == 1 else f"{cur['detail']}; {r['detail']}"
    return out
