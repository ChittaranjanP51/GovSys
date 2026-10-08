import pandas as pd
import streamlit as st
from common import render_check_badges, render_check_timeline

from governance import audit, data_governance, identity, model_governance, policy
from governance.checks import CHECK_IDS, CHECK_LABELS, summarize
from governance.config import settings


@st.cache_data(ttl=5, show_spinner=False)
def load_audit() -> list[dict]:
    return audit.read()


@st.cache_data(ttl=10, show_spinner=False)
def service_health() -> dict:
    health = {"Postgres": data_governance.healthy(), "OPA": policy.healthy(),
              "MLflow registry": model_governance.healthy(), "Ollama": bool(model_governance.ollama_models())}
    if settings.identity_provider == "keycloak":
        health["Keycloak"] = identity.keycloak_healthy()
    if audit.langfuse_enabled():
        health["Langfuse"] = audit.langfuse_healthy()
    return health


with st.container(horizontal=True, vertical_alignment="center"):
    for name, ok in service_health().items():
        st.badge(name, icon=":material/check_circle:" if ok else ":material/error:", color="green" if ok else "red")
    if st.button("Refresh", icon=":material/refresh:", type="tertiary"):
        load_audit.clear()
        service_health.clear()

rows = load_audit()
if not rows:
    st.info("No governed requests yet. Use the assistant first.", icon=":material/info:")
    st.stop()

chain = audit.verify_chain(rows)
df = pd.DataFrame([{
    "id": r["id"], "ts": r["ts"], "user": r["username"], "decision": r["final_decision"],
    "blocked_at": CHECK_LABELS.get(r["blocked_at"], "") if r["blocked_at"] else "",
    "agents": " → ".join(r["agent_path"] or []), "latency_ms": r["latency_ms"], "prompt": r["prompt_redacted"],
} for r in rows])
total, blocked = len(df), int((df.decision == "blocked").sum())

with st.container(horizontal=True):
    st.metric("Governed requests", total, border=True)
    st.metric("Blocked", blocked, f"{blocked / total:.0%} of requests", delta_color="off", delta_arrow="off", border=True)
    st.metric("Median latency", f"{int(df.latency_ms.median())} ms", border=True)
    st.metric("Audit chain", "Intact" if chain["intact"] else "BROKEN",
              f"{chain['rows']} rows hash-linked" if chain["intact"] else f"at id {chain.get('broken_at_id')}",
              delta_color="normal" if chain["intact"] else "inverse", delta_arrow="off", border=True)

per_check = []
for r in rows:
    s = summarize(r["checks"])
    for i, cid in enumerate(CHECK_IDS, 1):
        per_check.append({"control": f"{i}. {CHECK_LABELS[cid]}", "outcome": s[cid]["status"]})
pc = pd.DataFrame(per_check).value_counts().rename("requests").reset_index()

left, right = st.columns(2)
with left.container(border=True):
    st.markdown("**Outcome per control**")
    st.bar_chart(pc, x="control", y="requests", color="outcome", horizontal=True, sort=False,
                 alt="Pass, fail and not-reached counts for each of the seven governance controls")
with right.container(border=True):
    st.markdown("**Requests over time**")
    tl = df.assign(minute=pd.to_datetime(df.ts).dt.floor("h")).groupby(["minute", "decision"]).size().rename("requests").reset_index()
    st.bar_chart(tl, x="minute", y="requests", color="decision", alt="Allowed and blocked requests per hour")

st.markdown("**Recent requests** · select a row to inspect its checks")
sel = st.dataframe(df.sort_values("id", ascending=False), hide_index=True, on_select="rerun", selection_mode="single-row",
                   column_config={"ts": st.column_config.DatetimeColumn("time", format="YYYY-MM-DD HH:mm:ss"),
                                  "latency_ms": st.column_config.NumberColumn("latency", format="%d ms")},
                   alt="Audit log of governed requests")
if sel.selection.rows:
    rid = int(df.sort_values("id", ascending=False).iloc[sel.selection.rows[0]]["id"])
    r = next(x for x in rows if x["id"] == rid)
    with st.container(border=True):
        st.markdown(f"**Audit #{r['id']}** · {r['username']} · `{r['request_id']}`")
        render_check_badges(r["checks"])
        render_check_timeline(r["checks"])
        st.markdown(f"**Prompt (redacted):** {r['prompt_redacted']}")
        st.markdown(f"**Response (redacted):** {r['response_redacted']}")
        st.caption(f"row_hash `{r['row_hash']}` · prev_hash `{r['prev_hash']}`")
