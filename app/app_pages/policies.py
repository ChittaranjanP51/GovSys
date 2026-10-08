import json

import streamlit as st

from governance import identity, policy
from governance.config import settings

reg = json.loads((settings.opa_policy_dir / "data.json").read_text())["govsys"]
users = json.loads((settings.data_dir / "idp" / "users.json").read_text())

st.markdown("Every authorization decision goes to **Open Policy Agent** (`data.govsys.authz.decision`). "
            "If OPA is unreachable the system **fails closed**.")

sim, src = st.tabs(["Policy simulator", "Policy source"])
with sim:
    with st.container(border=True):
        c1, c2 = st.columns(2)
        user = c1.selectbox("Human principal", list(users), format_func=lambda u: f"{u} ({', '.join(users[u]['roles'])})")
        action = c2.segmented_control("Action", ["invoke_agent", "handoff", "tool_call", "read_pii"], default="tool_call")
        agent = c1.selectbox("Calling agent", list(reg["agents"]), index=2)
        target = c2.selectbox("Target agent", ["order", "billing", "admin"], disabled=action not in ("invoke_agent", "handoff"))
        all_tools = sorted({t for a in reg["agents"].values() for t in a["tools"]})
        tool = c1.selectbox("Tool", all_tools, index=all_tools.index("billing.issue_refund"), disabled=action != "tool_call")
        args = c2.text_input("Tool args (JSON)", '{"order_id": 1003, "amount": 300}', disabled=action != "tool_call")
        spoof = st.checkbox("Spoof agent SPIFFE ID", help="Present a SPIFFE ID from an untrusted domain")
    u = users[user]
    principal = {"sub": user, "roles": u["roles"], "status": u["status"]}
    agent_in = {"name": agent, "spiffe_id": "spiffe://evil.example/agent/" + agent if spoof else identity.spiffe_id(agent),
                "on_behalf_of": user}
    inp = {"action": action, "user": principal}
    if action in ("handoff", "tool_call"):
        inp["agent"] = agent_in
    if action in ("invoke_agent", "handoff"):
        inp["target_agent"] = target
    if action == "tool_call":
        try:
            inp |= {"tool": tool, "args": json.loads(args or "{}")}
        except json.JSONDecodeError:
            st.error("Args must be valid JSON")
            st.stop()
    d = policy.evaluate(inp)
    if d.allow:
        st.success("**ALLOW**", icon=":material/check_circle:")
    else:
        st.error("**DENY**: " + "; ".join(d.reasons), icon=":material/block:")
    with st.expander("OPA input"):
        st.json(inp)

with src:
    for f in sorted(settings.opa_policy_dir.glob("*")):
        with st.expander(f.name, expanded=f.name == "authz.rego"):
            st.code(f.read_text(), language="rego" if f.suffix == ".rego" else "json")
