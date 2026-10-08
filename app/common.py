"""Shared dashboard helpers: sys.path, session state, sign-in sidebar, check rendering."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from governance import identity  # noqa: E402
from governance.checks import CHECK_IDS, CHECK_LABELS, CHECK_LAYERS, summarize  # noqa: E402

STATUS_ICON = {"pass": ":material/check_circle:", "fail": ":material/cancel:", "skipped": ":material/remove_circle_outline:"}
STATUS_COLOR = {"pass": "green", "fail": "red", "skipped": "gray"}


def init_state() -> None:
    st.session_state.setdefault("token", None)
    st.session_state.setdefault("claims", None)
    st.session_state.setdefault("messages", [])


def current_user() -> dict | None:
    """Re-verify the session token on every rerun (expired / suspended -> signed out)."""
    tok = st.session_state.get("token")
    if not tok:
        return None
    try:
        st.session_state.claims = identity.verify_user_token(tok)
        return st.session_state.claims
    except identity.AuthError as e:
        st.session_state.token = st.session_state.claims = None
        st.toast(f"Signed out: {e}", icon=":material/lock:")
        return None


def is_admin(claims: dict | None) -> bool:
    return bool(claims) and "admin" in claims.get("roles", [])


def sign_in_form() -> None:
    with st.form("login", border=True):
        st.markdown("**Sign in**")
        u = st.text_input("Username", placeholder="alice")
        p = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in", icon=":material/login:", width="stretch"):
            try:
                st.session_state.token = identity.login(u.strip(), p)
                st.session_state.messages = []
                st.rerun()
            except identity.AuthError as e:
                st.error(str(e), icon=":material/lock:")
    with st.expander("Demo accounts"):
        st.table({"User": ["alice", "bob", "fiona", "carol", "ian", "mallory"],
                  "Password": ["Alice@123", "Bob@123", "Fiona@123", "Carol@123", "Ian@123", "Mallory@123"],
                  "Roles": ["support", "finance", "finance + finance_manager", "admin", "intern", "support (suspended)"]})


def render_check_badges(checks: list[dict]) -> None:
    summary = summarize(checks)
    with st.container(horizontal=True, gap="small"):
        for i, cid in enumerate(CHECK_IDS, 1):
            s = summary[cid]["status"]
            st.badge(f"{i}. {CHECK_LABELS[cid]}", icon=STATUS_ICON[s], color=STATUS_COLOR[s])


def render_check_timeline(checks: list[dict]) -> None:
    """One step per check execution, in the order the graph ran them."""
    if not checks:
        st.caption("No checks ran.")
        return
    for c in checks:
        label = f"{CHECK_LABELS[c['check']]} · {c['latency_ms']:.0f} ms"
        with st.status(label, type="step", state="complete" if c["status"] == "pass" else "error", expanded=False):
            st.caption(CHECK_LAYERS[c["check"]])
            st.markdown(c["detail"])
            if c.get("evidence"):
                st.json(c["evidence"], expanded=False)
