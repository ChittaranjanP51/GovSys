import pandas as pd
import streamlit as st

from governance import redteam
from governance.checks import CHECK_LABELS

st.markdown("Adversarial scenarios run through the **real** agent graph (and are audited), plus direct database "
            "probes that try to exceed each agent role's grants. A scenario passes when it is blocked by the "
            "expected control.")

if st.button("Run red-team suite", icon=":material/play_arrow:", type="primary"):
    with st.spinner("Attacking the system..."):
        redteam.run_all(use_llm=False)
    st.toast("Red-team run recorded in logs/redteam.jsonl", icon=":material/bug_report:")

res = redteam.latest_run()
if not res:
    st.info("No red-team run recorded yet.", icon=":material/info:")
    st.stop()

passed = sum(r["passed"] for r in res)
with st.container(horizontal=True):
    st.metric("Controls verified", f"{passed}/{len(res)}", border=True)
    st.metric("Last run (UTC)", res[0]["ts"][:19].replace("T", " "), border=True)

df = pd.DataFrame([{"id": r["id"], "result": "PASS" if r["passed"] else "FAIL", "scenario": r["title"],
                    "expected control": CHECK_LABELS.get(r["expected"], r["expected"]),
                    "blocked at": CHECK_LABELS.get(r["blocked_at"], r["blocked_at"] or "not blocked"),
                    "evidence": r["detail"]} for r in res])
st.dataframe(df, hide_index=True, alt="Red-team scenario results",
             column_config={"result": st.column_config.TextColumn(width="small")})
