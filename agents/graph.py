"""Multi-agent system as an explicit LangGraph state graph.

    authenticate -> input_guardrails -> model_gate -> supervisor
        supervisor -> {order_agent | billing_agent | admin_agent | respond}
        order_agent -> billing_agent   (governed agent-to-agent handoff)
        *_agent -> respond -> output_guardrails -> audit
    any gate failure -> blocked -> audit

Every edge that crosses a trust boundary is a governance check:
  1 identity  2 input_guardrails  3 model_approval  4 agent_authz (per handoff)
  5 tool_authz (per tool call)  6 data_access (per tool call)  7 output_guardrails
"""
from __future__ import annotations

import operator
import re
import time
import uuid
from typing import Annotated, Any, TypedDict

import jwt
import psycopg
from langgraph.graph import END, START, StateGraph

from governance import audit, guardrails_layer, identity, model_governance, policy
from governance.checks import CHECK_LABELS, FAIL, PASS, CheckResult, timed
from governance.config import settings
from governance.data_governance import AGENT_DB_ROLE, agent_connection, govern_rows

from . import llm, tools


class GovState(TypedDict, total=False):
    # inputs
    request_id: str
    message: str
    user_token: str
    requested_model: str | None
    use_llm: bool
    redteam: dict
    started: float
    # derived
    user: dict
    clean_message: str
    model: str | None
    route: str
    agent_tokens: dict
    pending_handoff: str | None
    pii_allowed: bool
    blocked: bool
    blocked_at: str | None
    response: str
    response_source: str
    audit_id: int | None
    audit_error: str | None
    # accumulated (reducers append)
    agent_path: Annotated[list, operator.add]
    checks: Annotated[list, operator.add]
    tool_calls: Annotated[list, operator.add]
    facts: Annotated[list, operator.add]


def _chk(check: str, ok: bool, detail: str, ms: float, **evidence) -> dict:
    return CheckResult(check, PASS if ok else FAIL, detail, evidence, ms).to_dict()


def _block(check: str, update: dict) -> dict:
    return update | {"blocked": True, "blocked_at": check}


# ------------------------------------------------------------- 1. identity
def authenticate(state: GovState) -> dict:
    with timed() as t:
        try:
            claims = identity.verify_user_token(state.get("user_token", ""))
            err = None
        except identity.AuthError as e:
            claims, err = {}, str(e)
    if err:
        try:   # record who the token *claims* to be, clearly marked as unverified
            claimed = jwt.decode(state.get("user_token", ""), options={"verify_signature": False}).get("sub")
        except jwt.PyJWTError:
            claimed = None
        user = {"sub": f"{claimed} (unverified)" if claimed else None, "roles": []}
        return _block("identity", {"user": user, "checks": [_chk("identity", False, err, t.ms, claimed_sub=claimed)]})
    detail = f"{claims['sub']} verified ({', '.join(claims['roles'])}) via {settings.identity_provider} IdP"
    return {"user": claims, "checks": [_chk("identity", True, detail, t.ms, sub=claims["sub"],
                                            roles=claims["roles"], issuer=claims.get("iss"))]}


# ----------------------------------------------------- 2. input guardrails
def input_guardrails(state: GovState) -> dict:
    with timed() as t:
        g = guardrails_layer.check_input(state["message"])
    upd = {"clean_message": g.text,
           "checks": [_chk("input_guardrails", g.passed, g.detail, t.ms, engine=g.engine,
                           violations=g.violations, redacted=list(g.redactions))]}
    return upd if g.passed else _block("input_guardrails", upd)


# ------------------------------------------------------ 3. model approval
def model_gate(state: GovState) -> dict:
    with timed() as t:
        ok, detail, ev = model_governance.gate(state.get("requested_model"))
    upd = {"model": ev.get("ollama_model") if ok else None,
           "checks": [_chk("model_approval", ok, detail, t.ms, **{k: v for k, v in ev.items() if k != "model_card"})]}
    return upd if ok else _block("model_approval", upd)


# --------------------------------------------------- routing / supervisor
ORDER_ACTION = r"\b(cancel|return|track|status|ship|shipped|deliver|delivered|where is)\b"
BILLING_KW = r"\b(invoice|refund|bill|billing|payment|paid|charge|charged)\b"
ADMIN_KW = r"\b(staff|employees?|users?|accounts?|roles?|audit|access review|governance summary)\b"


def keyword_route(msg: str) -> str | None:
    m = msg.lower()
    # "cancel order 1002 and refund it" starts at the order agent, which hands off to billing.
    if re.search(BILLING_KW, m) and not re.search(r"\b(cancel|return)", m):
        return "billing"
    if re.search(ORDER_ACTION, m):
        return "order"
    if re.search(BILLING_KW, m):
        return "billing"
    if re.search(ADMIN_KW, m):
        return "admin"
    if re.search(r"\border\b", m):
        return "order"
    return None


def _delegate(state: GovState, from_agent: str, from_token: str | None, target: str, chain: list[str]) -> tuple[dict, str | None]:
    """Governed handoff: verify caller identity, ask OPA, mint + verify the target's token."""
    user = state["user"]
    with timed() as t:
        reasons, ev = [], {"from": from_agent, "to": target, "chain": chain + [target]}
        if from_token is None:   # supervisor is the entry agent: obtain its workload identity
            from_token = identity.issue_agent_token(from_agent, user, [])
        try:
            caller = identity.verify_agent_token(from_token, from_agent)
            ev["caller_spiffe_id"] = caller["sub"]
        except identity.AuthError as e:
            caller, reasons = {}, [f"caller identity invalid: {e}"]
        if not reasons and from_agent == "supervisor":
            d = policy.can_invoke_agent(user, target)
            reasons += [] if d else d.reasons
        if not reasons:
            d = policy.can_handoff(user, caller, target)
            reasons += [] if d else d.reasons
        token = None
        if not reasons:
            token = identity.issue_agent_token(target, user, chain)
            if state.get("redteam", {}).get("forge_agent_token"):
                token = identity.forge_agent_token(target, user["sub"])
            try:
                tc = identity.verify_agent_token(token, target)
                ev["target_spiffe_id"], ev["delegated_for"] = tc["sub"], tc["act"]["sub"]
            except identity.AuthError as e:
                reasons, token = [f"target identity invalid: {e}"], None
    ok = not reasons
    detail = (f"{from_agent} -> {target} authorized; {target} holds SVID {identity.spiffe_id(target)}"
              if ok else "; ".join(reasons))
    return _chk("agent_authz", ok, detail, t.ms, **ev), token


def supervisor(state: GovState) -> dict:
    route = keyword_route(state["clean_message"])
    how = "keywords"
    if route is None and state.get("use_llm", settings.llm_enabled) and state.get("model"):
        try:
            route, how = llm.classify_intent(state["model"], state["clean_message"]), "llm"
        except llm.LLMError:
            route = None
    route = route or "none"
    upd: dict[str, Any] = {"route": route, "agent_path": ["supervisor"], "agent_tokens": {}}
    if route == "none":
        return upd
    chk, token = _delegate(state, "supervisor", None, route, ["supervisor"])
    chk["evidence"]["routed_by"] = how
    upd["checks"] = [chk]
    if token is None:
        return _block("agent_authz", upd)
    upd["agent_tokens"] = {route: token}
    return upd


# ------------------------------------------------------- agent machinery
class AgentCtx:
    """Executes governed tool calls for one agent and collects state updates."""

    def __init__(self, state: GovState, agent: str):
        self.state, self.agent = state, agent
        self.user = state["user"]
        self.token = state.get("agent_tokens", {}).get(agent)
        self.upd: dict[str, Any] = {"agent_path": [agent], "checks": [], "tool_calls": [], "facts": [],
                                    "pending_handoff": None}
        self.blocked = False
        self.pii_allowed = policy.can_read_pii(self.user).allow
        self.upd["pii_allowed"] = self.pii_allowed

    def _stop(self, check: str):
        self.blocked = True
        self.upd |= {"blocked": True, "blocked_at": check}

    def call(self, tool: str, args: dict, exec_extra: dict | None = None) -> list[dict] | None:
        if self.blocked:
            return None
        # 5. tool authorization: re-verify the agent's SVID, then ask OPA
        with timed() as t:
            try:
                claims = identity.verify_agent_token(self.token or "", self.agent)
                d = policy.can_call_tool(self.user, claims, tool, args)
                ok, reasons = d.allow, d.reasons
            except identity.AuthError as e:
                ok, reasons, claims = False, [f"agent identity invalid: {e}"], {}
        detail = f"{self.agent} -> {tool}({args}) allowed" if ok else "; ".join(reasons)
        self.upd["checks"].append(_chk("tool_authz", ok, detail, t.ms, agent=self.agent, tool=tool, args=args,
                                       spiffe_id=claims.get("sub"), on_behalf_of=self.user["sub"]))
        if not ok:
            self.upd["tool_calls"].append({"agent": self.agent, "tool": tool, "args": args, "decision": "denied",
                                           "reasons": reasons})
            self.upd["facts"].append({"tool": tool, "denied": True, "reasons": reasons})
            self._stop("tool_authz")
            return None
        # 6. data access under the agent's own DB role + catalog-driven masking
        role = AGENT_DB_ROLE[self.agent]
        with timed() as t:
            err, rows, meta = None, [], {}
            try:
                rows = tools.execute(tool, args | (exec_extra or {}))
                rows, meta = govern_rows(rows, tools.TOOLS[tool].source, self.pii_allowed)
            except psycopg.errors.InsufficientPrivilege as e:
                err = f"database denied role {role}: {str(e).splitlines()[0]}"
            except tools.ToolError as e:
                rows, meta = [], {"business_error": str(e)}
        if err:
            self.upd["checks"].append(_chk("data_access", False, err, t.ms, db_role=role, tool=tool))
            self.upd["tool_calls"].append({"agent": self.agent, "tool": tool, "args": args, "decision": "db_denied"})
            self._stop("data_access")
            return None
        masked = meta.get("masked") or []
        detail = f"ran as DB role '{role}'" + (f"; masked PII {masked}" if masked else "")
        if meta.get("removed"):
            detail += f"; removed restricted {meta['removed']}"
        self.upd["checks"].append(_chk("data_access", True, detail, t.ms, db_role=role, tool=tool, **meta))
        status = "error" if meta.get("business_error") else "executed"
        self.upd["tool_calls"].append({"agent": self.agent, "tool": tool, "args": args, "decision": status,
                                       "rows": len(rows), **({"error": meta["business_error"]} if status == "error" else {})})
        self.upd["facts"].append({"tool": tool, "args": args, **({"error": meta["business_error"]} if status == "error" else {"result": rows})})
        return rows if status == "executed" else None

    def handoff(self, target: str) -> None:
        if self.blocked:
            return
        chain = list(self.state.get("agent_path", [])) + [self.agent]
        chk, token = _delegate(self.state, self.agent, self.token, target, chain[:-1] + [self.agent])
        self.upd["checks"].append(chk)
        if token is None:
            self._stop("agent_authz")
            return
        self.upd["agent_tokens"] = self.state.get("agent_tokens", {}) | {target: token}
        self.upd["pending_handoff"] = target

    def note(self, text: str) -> None:
        self.upd["facts"].append({"note": text})


def _order_id(m: str) -> int | None:
    x = re.search(r"\border\s*(?:no\.?|number|#)?\s*#?(\d{3,6})\b", m) or re.search(r"#(\d{3,6})\b", m) \
        or re.search(r"\b(1\d{3})\b", m)
    return int(x.group(1)) if x else None


def _amount(m: str) -> float | None:
    x = re.search(r"\$\s?(\d+(?:\.\d{1,2})?)", m) or re.search(r"(\d+(?:\.\d{1,2})?)\s*(?:usd|dollars)\b", m) \
        or re.search(r"\bamount\s*(?:of)?\s*(\d+(?:\.\d{1,2})?)", m)
    return float(x.group(1)) if x else None


# ------------------------------------------------------------------ agents
def order_agent(state: GovState) -> dict:
    ctx, m = AgentCtx(state, "order"), state["clean_message"].lower()
    if state.get("redteam", {}).get("compromised_query"):
        # Simulates a compromised agent issuing raw SQL outside its mandate. Policy is bypassed
        # on purpose: the database role is the last line of defence.
        with timed() as t:
            try:
                with agent_connection("order") as conn:
                    conn.execute("SELECT full_name, national_id FROM sales.customers").fetchall()
                err = None
            except psycopg.errors.InsufficientPrivilege as e:
                err = str(e).splitlines()[0]
        ctx.upd["checks"].append(_chk("data_access", err is None,
                                      f"database denied role agent_order: {err}" if err else "restricted column readable!",
                                      t.ms, db_role="agent_order", attempted="SELECT national_id FROM sales.customers"))
        ctx.upd["tool_calls"].append({"agent": "order", "tool": "raw_sql", "args": {}, "decision": "db_denied" if err else "executed"})
        ctx._stop("data_access")
        return ctx.upd
    oid = _order_id(m)
    cust = re.search(r"customer\s*(?:id)?\s*#?(\d+)", m)
    new_status = re.search(r"\b(?:as|to)\s+(placed|shipped|delivered|cancelled|canceled|returned)\b", m)
    if oid and new_status:
        ctx.call("order.update_status", {"order_id": oid, "status": new_status.group(1).replace("canceled", "cancelled")})
    elif oid and re.search(r"\bcancel", m):
        ctx.call("order.update_status", {"order_id": oid, "status": "cancelled"})
    elif oid and re.search(r"\breturn(ed)?\b", m) and "status" not in m:
        ctx.call("order.update_status", {"order_id": oid, "status": "returned"})
    elif cust and not oid:
        ctx.call("order.customer_orders", {"customer_id": int(cust.group(1))})
    elif oid:
        ctx.call("order.lookup", {"order_id": oid})
    else:
        ctx.note("No order number found. Ask the user for the order number (e.g. 1001).")
    if oid and re.search(BILLING_KW, m):
        ctx.handoff("billing")
    return ctx.upd


def billing_agent(state: GovState) -> dict:
    ctx, m = AgentCtx(state, "billing"), state["clean_message"].lower()
    ctx.upd["pending_handoff"] = None
    oid = _order_id(m)
    if re.search(r"\brefund", m) and re.search(r"\b(history|list|past|previous)\b", m):
        ctx.call("billing.refund_history", {"order_id": oid} if oid else {})
    elif re.search(r"\brefund", m) and oid:
        amt = _amount(m)
        if amt is None:   # "full refund": read the invoice first (itself a governed call)
            inv = ctx.call("billing.get_invoice", {"order_id": oid})
            amt = float(inv[0]["amount"]) if inv else None
        if amt is not None:
            spiffe = identity.verify_agent_token(ctx.token, "billing")["sub"] if ctx.token else ""
            ctx.call("billing.issue_refund", {"order_id": oid, "amount": amt},
                     exec_extra={"reason": state["clean_message"][:200], "requested_by": state["user"]["sub"],
                                 "agent_spiffe_id": spiffe})
    elif oid:
        ctx.call("billing.get_invoice", {"order_id": oid})
    else:
        ctx.note("No order number found. Ask the user which order's invoice or refund they mean.")
    return ctx.upd


def admin_agent(state: GovState) -> dict:
    ctx, m = AgentCtx(state, "admin"), state["clean_message"].lower()
    if re.search(r"\b(audit|governance|blocked|decisions?)\b", m):
        ctx.call("admin.audit_summary", {})
    else:
        ctx.call("admin.list_staff", {})
    return ctx.upd


# ----------------------------------------------------------------- respond
CAPABILITIES = ("I can help with **orders** (status, cancellation, returns), **billing** (invoices, refunds) "
                "and, for administrators, **staff & audit** questions. Please mention an order number, e.g. "
                "'What is the status of order 1001?'")


def _template(facts: list[dict]) -> str:
    lines = []
    for f in facts:
        if "note" in f:
            lines.append(f["note"])
        elif f.get("denied"):
            lines.append(f"Action `{f['tool']}` was denied: {'; '.join(f['reasons'])}")
        elif "error" in f:
            lines.append(f"`{f['tool']}` could not complete: {f['error']}")
        else:
            for row in f["result"][:10]:
                lines.append("- " + ", ".join(f"{k}: {v}" for k, v in row.items()))
            if not f["result"]:
                lines.append(f"`{f['tool']}` returned no records.")
    return "\n".join(lines) or "No information available."


def respond(state: GovState) -> dict:
    if state.get("route") == "none":
        return {"response": CAPABILITIES, "response_source": "template"}
    facts = state.get("facts", [])
    if state.get("use_llm", settings.llm_enabled) and state.get("model"):
        try:
            text = llm.compose_answer(state["model"], state["clean_message"], state["user"].get("name", ""), facts)
            return {"response": text, "response_source": f"llm:{state['model']}"}
        except llm.LLMError as e:
            return {"response": _template(facts), "response_source": f"template (LLM unavailable: {str(e)[:80]})"}
    return {"response": _template(facts), "response_source": "template"}


# ---------------------------------------------------- 7. output guardrails
def output_guardrails(state: GovState) -> dict:
    with timed() as t:
        g = guardrails_layer.check_output(state.get("response", ""), state.get("pii_allowed", False))
    upd = {"checks": [_chk("output_guardrails", g.passed, g.detail, t.ms, engine=g.engine,
                           violations=g.violations, redacted=list(g.redactions))]}
    if not g.passed:
        return _block("output_guardrails", upd | {"response": "Response withheld by output guardrails."})
    return upd | {"response": g.text}


# --------------------------------------------------------- blocked + audit
def blocked(state: GovState) -> dict:
    at = state.get("blocked_at")
    fail = next((c for c in reversed(state.get("checks", [])) if c["check"] == at and c["status"] == FAIL), None)
    reason = fail["detail"] if fail else "governance violation"
    done = [f for f in state.get("facts", []) if "result" in f]
    msg = f"Request blocked at **{CHECK_LABELS.get(at, at)}**: {reason}"
    if done:
        msg += "\n\nCompleted before the block:\n" + _template(done)
    return {"response": msg, "response_source": "governance"}


def audit_node(state: GovState) -> dict:
    user = state.get("user", {})
    rec = {"request_id": state["request_id"], "username": user.get("sub"), "roles": user.get("roles", []),
           "agent_path": state.get("agent_path", []), "final_decision": "blocked" if state.get("blocked") else "allowed",
           "blocked_at": state.get("blocked_at"), "checks": state.get("checks", []),
           "tool_calls": state.get("tool_calls", []), "model": state.get("model"),
           "prompt_redacted": state.get("clean_message") or guardrails_layer.redact(
               state.get("message", ""), guardrails_layer.find_pii(state.get("message", ""))),
           "response_redacted": state.get("response", ""),
           "latency_ms": int((time.perf_counter() - state["started"]) * 1000)}
    try:
        entry = audit.write(rec)
        return {"audit_id": entry["id"]}
    except Exception as e:  # noqa: BLE001 - surface, never hide, audit failures
        return {"audit_error": f"{e.__class__.__name__}: {e}"}


# ------------------------------------------------------------------- graph
def _gate(next_node: str):
    return lambda s: "blocked" if s.get("blocked") else next_node


def _after_supervisor(s: GovState) -> str:
    if s.get("blocked"):
        return "blocked"
    return {"order": "order_agent", "billing": "billing_agent", "admin": "admin_agent"}.get(s["route"], "respond")


def _after_order(s: GovState) -> str:
    if s.get("blocked"):
        return "blocked"
    return "billing_agent" if s.get("pending_handoff") == "billing" else "respond"


def build_graph():
    g = StateGraph(GovState)
    for name, fn in [("authenticate", authenticate), ("input_guardrails", input_guardrails),
                     ("model_gate", model_gate), ("supervisor", supervisor), ("order_agent", order_agent),
                     ("billing_agent", billing_agent), ("admin_agent", admin_agent), ("respond", respond),
                     ("output_guardrails", output_guardrails), ("blocked", blocked), ("audit", audit_node)]:
        g.add_node(name, fn)
    g.add_edge(START, "authenticate")
    g.add_conditional_edges("authenticate", _gate("input_guardrails"), ["input_guardrails", "blocked"])
    g.add_conditional_edges("input_guardrails", _gate("model_gate"), ["model_gate", "blocked"])
    g.add_conditional_edges("model_gate", _gate("supervisor"), ["supervisor", "blocked"])
    g.add_conditional_edges("supervisor", _after_supervisor,
                            ["order_agent", "billing_agent", "admin_agent", "respond", "blocked"])
    g.add_conditional_edges("order_agent", _after_order, ["billing_agent", "respond", "blocked"])
    g.add_conditional_edges("billing_agent", _gate("respond"), ["respond", "blocked"])
    g.add_conditional_edges("admin_agent", _gate("respond"), ["respond", "blocked"])
    g.add_conditional_edges("respond", lambda s: "output_guardrails", ["output_guardrails"])
    g.add_conditional_edges("output_guardrails", lambda s: "audit", ["audit"])
    g.add_edge("blocked", "audit")
    g.add_edge("audit", END)
    return g.compile()


GRAPH = build_graph()


def run(message: str, user_token: str, requested_model: str | None = None, use_llm: bool | None = None,
        redteam: dict | None = None) -> GovState:
    state: GovState = {"request_id": str(uuid.uuid4()), "message": message, "user_token": user_token,
                       "requested_model": requested_model, "redteam": redteam or {}, "started": time.perf_counter(),
                       "use_llm": settings.llm_enabled if use_llm is None else use_llm,
                       "checks": [], "tool_calls": [], "facts": [], "agent_path": []}
    return GRAPH.invoke(state)
