import streamlit as st

from governance import model_governance
from governance.config import settings

st.markdown(f"Registered model **`{settings.registered_model}`** · serving alias **`{settings.model_alias}`** · "
            f"MLflow UI: http://127.0.0.1:5000 (start with `python scripts/services.py start mlflow`)")

versions = model_governance.registry_versions(force=True)
installed = set(model_governance.ollama_models())

for v in versions:
    approved, detail, _ = model_governance.gate(v.get("ollama_model"))
    with st.container(border=True):
        with st.container(horizontal=True, vertical_alignment="center"):
            st.markdown(f"#### v{v['version']} · `{v.get('ollama_model')}`")
            if v["alias"]:
                st.badge(v["alias"], icon=":material/star:", color="violet")
            st.badge("gate: approved" if approved else "gate: blocked",
                     icon=":material/check_circle:" if approved else ":material/block:", color="green" if approved else "red")
            st.badge("installed in Ollama" if v.get("ollama_model") in installed else "not installed",
                     color="gray")
        st.caption(detail)
        st.table({k: [v.get(k, "-")] for k in ["approval_status", "risk_tier", "eval_passed", "eval_groundedness",
                                                "eval_toxicity", "intended_use", "approved_by", "license"]},
                 hide_index=True, alt=f"Governance tags of version {v['version']}")
        with st.form(f"approve_{v['version']}", border=False):
            with st.container(horizontal=True, vertical_alignment="bottom"):
                status = st.segmented_control("Governance board decision", ["approved", "pending_review", "rejected"],
                                              default=v.get("approval_status"), key=f"st_{v['version']}")
                if st.form_submit_button("Record decision", icon=":material/gavel:"):
                    model_governance.set_approval(v["version"], status, st.session_state.claims["sub"])
                    st.toast(f"v{v['version']} -> {status}", icon=":material/gavel:")
                    st.rerun()

st.caption("The runtime gate requires approval_status=approved, eval_passed=true and risk_tier in {low, medium}. "
           "Decisions are written to MLflow as tags, with the approver recorded.")
