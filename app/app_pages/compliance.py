import streamlit as st

from compliance.report import generate, to_html

st.markdown("Generates an evidence-based report from live systems: the hash-verified audit log, OPA policy bundle "
            "and unit tests, MLflow registry, effective Postgres privileges, data catalog and the latest red-team run.")

with st.container(horizontal=True, vertical_alignment="bottom"):
    window = st.segmented_control("Window", ["All time", "Last 30 days", "Last 7 days", "Last 24 hours"], default="All time")
    go = st.button("Generate report", icon=":material/description:", type="primary")

days = {"All time": None, "Last 30 days": 30, "Last 7 days": 7, "Last 24 hours": 1}[window or "All time"]
if go:
    with st.spinner("Collecting evidence..."):
        md, stamp, ev = generate(days)
    st.session_state.report = (md, stamp)

if "report" in st.session_state:
    md, stamp = st.session_state.report
    with st.container(horizontal=True):
        st.download_button("Markdown", md, f"compliance_report_{stamp}.md", "text/markdown", icon=":material/download:")
        st.download_button("HTML", to_html(md), f"compliance_report_{stamp}.html", "text/html", icon=":material/download:")
        st.caption(f"Also saved to reports/compliance_report_{stamp}.md / .html")
    with st.container(border=True):
        st.markdown(md)
