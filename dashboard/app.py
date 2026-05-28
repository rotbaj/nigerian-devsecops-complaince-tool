"""
Nigerian Fintech DevSecOps - Compliance Dashboard
Run with: streamlit run dashboard/app.py
"""

import streamlit as st
import pandas as pd
import json
import os
import sys
from datetime import datetime

# Fix 4: Robust import regardless of working directory.
# Resolves the parent package so `compliance_engine` is always findable
# whether you run from the project root or from the dashboard/ folder.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from compliance_engine.scanner import scan_path, save_report

# ─── Page Config ───────────────────────────────────────────────
st.set_page_config(
    page_title="Nigerian Fintech DevSecOps Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# ─── Sidebar ───────────────────────────────────────────────────
st.sidebar.title("🛡️ DevSecOps Dashboard")
st.sidebar.markdown("**Nigerian Fintech Compliance Engine**")
st.sidebar.markdown("---")

mode = st.sidebar.radio("Mode", ["📂 Scan Directory", "📄 Load Report"])
fail_on_warning = st.sidebar.checkbox("Fail on WARNING", value=False)

# Fix 2: Resolve report_path relative to THIS file, not the current working
# directory. Without this, the path breaks when streamlit is launched from
# anywhere other than the project root.
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
report_path = os.path.join(BASE_DIR, "reports", "scan_report.json")

# ─── Header ────────────────────────────────────────────────────
st.title("🛡️ Nigerian Fintech DevSecOps Compliance Dashboard")
st.caption("Automated security & NDPA 2023 compliance scanning for Nigerian Fintech CI/CD pipelines")
st.markdown("---")

# ─── Scan or Load ──────────────────────────────────────────────
result_data = None

if mode == "📂 Scan Directory":
    scan_target = st.text_input("Enter path to scan:", value=BASE_DIR)
    col1, col2 = st.columns([1, 4])
    with col1:
        run_scan = st.button("🔍 Run Scan", type="primary")

    if run_scan:
        # Fix 2: Validate the path exists before trying to scan it
        if not os.path.exists(scan_target):
            st.error(f"❌ Path not found: `{scan_target}`. Please enter a valid file or directory.")
        else:
            try:
                with st.spinner(f"Scanning `{scan_target}`..."):
                    result = scan_path(scan_target)
                    if fail_on_warning:
                        result.passed = result.passed and result.warning == 0
                    # Fix 2: Ensure reports/ directory exists before writing —
                    # prevents crash on a fresh clone where reports/ doesn't exist yet
                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                    save_report(result, report_path)
                    result_data = result.to_dict()
                st.success("Scan complete!")
            except Exception as e:
                st.error(f"❌ Scan failed unexpectedly: {e}")

elif mode == "📄 Load Report":
    # Fix 2: Always guard with os.path.exists() — prevents FileNotFoundError
    # crash on a fresh clone before any scan has been run.
    if not os.path.exists(report_path):
        st.warning(
            "⚠️ No scan report found at `reports/scan_report.json`.\n\n"
            "Run a scan first using **📂 Scan Directory** mode above, or via CLI:\n"
            "```bash\npython compliance_engine/scanner.py .\n```"
        )
    else:
        try:
            with open(report_path) as f:
                result_data = json.load(f)
            st.info(f"Loaded report from `{report_path}`")
        except (json.JSONDecodeError, IOError) as e:
            st.error(f"❌ Could not read report file: {e}")

# ─── Results ───────────────────────────────────────────────────
if result_data:
    findings = result_data.get("findings", [])

    # ── Status Banner ──
    passed = result_data.get("passed", False)
    if passed:
        st.success("## ✅ BUILD PASSED — No critical or high severity issues found.")
    else:
        st.error("## ❌ BUILD FAILED — Critical or high severity issues require remediation before merge.")

    # ── Metric Cards ──
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Files Scanned", result_data.get("files_scanned", 0))
    m2.metric("Total Findings", result_data.get("total_findings", 0))
    m3.metric("🔴 Critical", result_data.get("critical", 0))
    m4.metric("🟠 High", result_data.get("high", 0))
    m5.metric("🟡 Warnings", result_data.get("warning", 0))

    st.markdown("---")

    if not findings:
        st.balloons()
        st.success("🎉 No findings detected. Your code is clean!")
    else:
        # ── Filters ──
        st.subheader("🔎 Filter Findings")
        col_sev, col_cat = st.columns(2)
        all_severities = ["CRITICAL", "HIGH", "WARNING"]
        all_categories = sorted(set(f["category"] for f in findings))

        selected_sev = col_sev.multiselect("Severity", all_severities, default=all_severities)
        selected_cat = col_cat.multiselect("Category", all_categories, default=all_categories)

        filtered = [
            f for f in findings
            if f["severity"] in selected_sev and f["category"] in selected_cat
        ]

        # ── Findings Table ──
        st.subheader(f"📋 Findings ({len(filtered)} shown)")
        SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡"}

        for finding in filtered:
            icon = SEVERITY_ICON.get(finding["severity"], "⚪")
            with st.expander(
                f"{icon} [{finding['severity']}] {finding['rule_id']} — {finding['name']} | `{finding['filename']}:{finding['line_number']}`"
            ):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Category:** `{finding['category'].upper()}`")
                    st.markdown(f"**File:** `{finding['filename']}`")
                    st.markdown(f"**Line:** {finding['line_number']}")
                    st.code(finding["line_content"], language="text")
                with c2:
                    st.markdown(f"**Description:**\n{finding['description']}")
                    st.info(f"🔧 **Remediation:** {finding['remediation']}")

        # ── Findings by Category ──
        st.markdown("---")
        st.subheader("📊 Findings by Category")
        category_counts = {}
        for f in findings:
            category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1

        chart_df = pd.DataFrame.from_dict(
            {"Findings": category_counts}, orient="columns"
        )
        st.bar_chart(chart_df)

    # ── Scan Metadata ──
    st.markdown("---")
    st.caption(f"Scan timestamp: {result_data.get('scanned_at', 'N/A')} UTC")
