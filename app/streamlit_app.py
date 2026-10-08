import common  # noqa: F401  (sets sys.path)
import streamlit as st
from common import current_user, init_state, is_admin, sign_in_form

from governance.config import settings

st.set_page_config(page_title="GovSys - AI governance", page_icon=":material/shield_lock:", layout="wide")
init_state()
claims = current_user()

with st.sidebar:
    st.markdown("### :material/shield_lock: GovSys")
    st.caption("Governed multi-agent assistant")
    if claims:
        with st.container(border=True):
            st.markdown(f"**{claims.get('name') or claims['sub']}**")
            st.caption(f"{claims['sub']} · {', '.join(claims['roles'])}")
            if st.button("Sign out", icon=":material/logout:", width="stretch"):
                st.session_state.token = st.session_state.claims = None
                st.session_state.messages = []
                st.rerun()
    st.caption(f"IdP: `{settings.identity_provider}` · mode: `{settings.mode}`")

if not claims:
    st.title("GovSys", anchor=False)
    st.markdown("A multi-agent assistant for orders, billing and administration, with identity, policy, "
                "data, model, runtime and audit governance on every request.")
    left, _ = st.columns([1, 1])
    with left:
        sign_in_form()
    st.stop()

pages = [st.Page("app_pages/chat.py", title="Assistant", icon=":material/chat:", default=True)]
if is_admin(claims):
    pages += [
        st.Page("app_pages/monitor.py", title="Governance monitor", icon=":material/monitoring:"),
        st.Page("app_pages/models.py", title="Model registry", icon=":material/model_training:"),
        st.Page("app_pages/policies.py", title="Policies", icon=":material/policy:"),
        st.Page("app_pages/redteam.py", title="Red team", icon=":material/bug_report:"),
        st.Page("app_pages/compliance.py", title="Compliance report", icon=":material/verified:"),
    ]
page = st.navigation(pages, position="top")
page.run()
