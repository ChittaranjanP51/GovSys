"""Policy governance: every authorization decision is delegated to OPA.

Fail closed: if OPA is unreachable the action is denied, never allowed.
"""
from __future__ import annotations

import httpx

from .config import settings

DECISION_PATH = "/v1/data/govsys/authz/decision"
_http = httpx.Client(timeout=5)


class PolicyDecision:
    def __init__(self, allow: bool, reasons: list[str], input_: dict):
        self.allow, self.reasons, self.input = allow, reasons, input_

    def __bool__(self) -> bool:
        return self.allow

    def explain(self) -> str:
        return "allowed by policy" if self.allow else "; ".join(self.reasons) or "denied"


def _user(claims: dict) -> dict:
    return {"sub": claims.get("sub"), "roles": claims.get("roles", []), "status": claims.get("status")}


def evaluate(input_: dict) -> PolicyDecision:
    try:
        r = _http.post(f"{settings.opa_url}{DECISION_PATH}", json={"input": input_})
        r.raise_for_status()
        result = r.json().get("result")
    except Exception as e:  # noqa: BLE001 - any failure must deny
        return PolicyDecision(False, [f"policy engine unavailable (fail-closed): {e.__class__.__name__}"], input_)
    if result is None:
        return PolicyDecision(False, ["policy returned no decision (fail-closed)"], input_)
    return PolicyDecision(bool(result["allow"]), sorted(result.get("deny", [])), input_)


def can_invoke_agent(user: dict, agent: str) -> PolicyDecision:
    return evaluate({"action": "invoke_agent", "user": _user(user), "target_agent": agent})


def can_handoff(user: dict, agent_claims: dict, target: str) -> PolicyDecision:
    return evaluate({"action": "handoff", "user": _user(user), "target_agent": target,
                     "agent": _agent(agent_claims)})


def can_call_tool(user: dict, agent_claims: dict, tool: str, args: dict) -> PolicyDecision:
    return evaluate({"action": "tool_call", "user": _user(user), "tool": tool, "args": args,
                     "agent": _agent(agent_claims)})


def can_read_pii(user: dict) -> PolicyDecision:
    return evaluate({"action": "read_pii", "user": _user(user)})


def _agent(c: dict) -> dict:
    return {"name": c.get("agent"), "spiffe_id": c.get("sub"), "on_behalf_of": c.get("act", {}).get("sub")}


def healthy() -> bool:
    try:
        return httpx.get(f"{settings.opa_url}/health", timeout=2).status_code == 200
    except Exception:  # noqa: BLE001
        return False
