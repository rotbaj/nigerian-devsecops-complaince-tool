"""
Nigerian Fintech DevSecOps - Compliance Dashboard
Run with: streamlit run dashboard/app.py
"""

import streamlit as st
import pandas as pd
import altair as alt
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request

# Fix 4: Robust import regardless of working directory.
# Resolves the parent package so `compliance_engine` is always findable
# whether you run from the project root or from the dashboard/ folder.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from compliance_engine.scanner import scan_path, save_report, append_history

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
history_path = os.path.join(BASE_DIR, "reports", "scan_history.json")
REPO_NAME = os.path.basename(BASE_DIR)


def repo_relative(path):
    """Show paths scoped to the repo instead of the full file system."""
    p = str(path)
    if os.path.isabs(p):
        rel = os.path.relpath(p, BASE_DIR)
        if rel.startswith(".."):
            return p  # outside the repo — nothing shorter to show
        p = rel
    p = os.path.normpath(p)
    return REPO_NAME if p == "." else p


# Fallback for hosted deployments (e.g. Streamlit Community Cloud), where
# the app may not run from a git checkout so the remote can't be detected.
DEFAULT_GITHUB_REPO = "rotbaj/nigerian-devsecops-complaince-tool"


def detect_github_repo():
    """Owner/name of this repo's GitHub remote, else the deployment default."""
    try:
        url = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            cwd=BASE_DIR, text=True, timeout=5,
        ).strip()
    except Exception:
        return DEFAULT_GITHUB_REPO
    m = re.search(r"github\.com[:/]([^/]+/[^/\s]+?)(?:\.git)?$", url)
    return m.group(1) if m else DEFAULT_GITHUB_REPO


def fetch_ci_json(repo_slug, filename):
    """Read a results file from the repo's scan-results branch on GitHub."""
    url = f"https://raw.githubusercontent.com/{repo_slug}/scan-results/{filename}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.load(resp)


# Trivy reports published by the pipeline, in dashboard display order.
TRIVY_REPORTS = {
    "Docker image (known CVEs)": "trivy_image.json",
    "Vulnerable corpus (infrastructure)": "trivy_vulnerable.json",
    "Clean corpus (infrastructure)": "trivy_clean.json",
}


def summarize_trivy(report):
    """Flatten a Trivy JSON report into severity counts + display rows."""
    counts = {}
    rows = []
    for res in report.get("Results") or []:
        target = res.get("Target", "")
        for m in res.get("Misconfigurations") or []:
            sev = m.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            rows.append({
                "Severity": sev,
                "Issue": m.get("Title", m.get("ID", "")),
                "Where": target,
                "How to fix": m.get("Resolution", ""),
            })
        for v in res.get("Vulnerabilities") or []:
            sev = v.get("Severity", "UNKNOWN")
            counts[sev] = counts.get(sev, 0) + 1
            fixed = v.get("FixedVersion", "")
            rows.append({
                "Severity": sev,
                "Issue": f"{v.get('VulnerabilityID', '')}: {v.get('Title', '')}",
                "Where": f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')}",
                "How to fix": f"Upgrade to {fixed}" if fixed else "No fix released yet",
            })
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    rows.sort(key=lambda r: sev_rank.get(r["Severity"], 9))
    return counts, rows

# ─── Header ────────────────────────────────────────────────────
st.title("🛡️ Nigerian Fintech DevSecOps Compliance Dashboard")
st.caption("Automated security & NDPA 2023 compliance scanning for Nigerian Fintech CI/CD pipelines")
st.markdown("---")

# ─── Scan or Load ──────────────────────────────────────────────
result_data = None

if mode == "📂 Scan Directory":
    scan_target = st.text_input(
        "Enter path to scan:",
        value=".",
        help="Paths are relative to the project root ('.' scans the whole repo). "
             "To demo detection, scan the evaluation corpus directly: "
             "evaluation_data/vulnerable (100 bad files) or evaluation_data/clean "
             "(100 clean files). Excludes below never apply to the target itself.",
    )
    # Same default excludes as the CI pipeline — tests/ and evaluation_data/
    # intentionally contain synthetic secrets, so a scan of the PROJECT ROOT
    # would otherwise always report FAILED. These excludes only skip
    # subdirectories inside the target; scanning evaluation_data/ directly
    # as the target still works with this field untouched.
    exclude_input = st.text_input(
        "Exclude directories (comma-separated):",
        value="tests,evaluation_data",
        help="Directory names skipped at any depth inside the scan target. "
             "Clear this field to scan everything.",
    )
    col1, col2 = st.columns([1, 4])
    with col1:
        run_scan = st.button("🔍 Run Scan", type="primary")

    if run_scan:
        # Relative paths are resolved against the project root, not the
        # process working directory, so ". " and "evaluation_data/..." work
        # no matter where streamlit was launched from.
        resolved_target = (
            scan_target if os.path.isabs(scan_target)
            else os.path.normpath(os.path.join(BASE_DIR, scan_target))
        )
        display_target = repo_relative(resolved_target)
        # evaluation_data/ is git-ignored (synthetic secrets), so on a fresh
        # clone — including the hosted Streamlit Cloud app — it doesn't exist
        # until generated. Generate it on demand when it's the scan target.
        if not os.path.exists(resolved_target) and display_target.split(os.sep)[0] == "evaluation_data":
            generator = os.path.join(BASE_DIR, "generate_eval_data.py")
            if os.path.exists(generator):
                with st.spinner("Generating the 200-file evaluation corpus (first run only)..."):
                    subprocess.run(
                        [sys.executable, generator],
                        cwd=BASE_DIR, check=True, capture_output=True,
                    )
        # Fix 2: Validate the path exists before trying to scan it
        if not os.path.exists(resolved_target):
            st.error(f"❌ Path not found: `{display_target}`. Please enter a valid file or directory.")
        else:
            exclude_dirs = [d.strip() for d in exclude_input.split(",") if d.strip()]
            try:
                with st.spinner(f"Scanning `{display_target}`..."):
                    result = scan_path(resolved_target, exclude=exclude_dirs)
                    if fail_on_warning:
                        result.passed = result.passed and result.warning == 0
                    # Fix 2: Ensure reports/ directory exists before writing —
                    # prevents crash on a fresh clone where reports/ doesn't exist yet
                    os.makedirs(os.path.dirname(report_path), exist_ok=True)
                    save_report(result, report_path)
                    append_history(result, target=display_target, history_path=history_path)
                    # Streamlit reruns this whole script every time ANY widget
                    # changes, and the button only reads True on the run right
                    # after the click. Without session_state the results would
                    # vanish as soon as the user touches a filter or sort control.
                    st.session_state["scan_result"] = result.to_dict()
                st.success("Scan complete!")
            except Exception as e:
                st.error(f"❌ Scan failed unexpectedly: {e}")

    result_data = st.session_state.get("scan_result")

elif mode == "📄 Load Report":
    source = st.radio(
        "Report source:",
        ["🌐 Latest CI results", "📤 Upload a file", "💾 Local report file"],
        horizontal=True,
        help="CI results come from the scan-results branch that the pipeline "
             "publishes on every push — no terminal needed.",
    )

    if source == "🌐 Latest CI results":
        repo_slug = st.text_input(
            "GitHub repository (owner/name):",
            value=detect_github_repo(),
            help="The pipeline publishes results to this repo's scan-results branch.",
        )
        CI_REPORTS = {
            "Full repository scan": "scan_report.json",
            "Vulnerable corpus (evaluation)": "vulnerable_report.json",
            "Clean corpus (evaluation)": "clean_report.json",
        }
        which = st.selectbox("Which CI scan:", list(CI_REPORTS))
        if st.button("🔄 Fetch latest CI results", type="primary"):
            if not repo_slug.strip():
                st.error("❌ Enter the GitHub repository as owner/name.")
            else:
                try:
                    st.session_state["ci_report"] = fetch_ci_json(
                        repo_slug.strip(), CI_REPORTS[which]
                    )
                    st.session_state["ci_report_name"] = which
                    # Also pull the accumulated CI history so the trend
                    # chart can show the pipeline's view, not just local scans.
                    try:
                        st.session_state["ci_history"] = fetch_ci_json(
                            repo_slug.strip(), "scan_history.json"
                        )
                    except Exception:
                        st.session_state.pop("ci_history", None)
                    # And the Trivy reports (best-effort: absent until the
                    # pipeline has run with Trivy export enabled).
                    ci_trivy = {}
                    for label, fname in TRIVY_REPORTS.items():
                        try:
                            ci_trivy[label] = fetch_ci_json(repo_slug.strip(), fname)
                        except Exception:
                            pass
                    st.session_state["ci_trivy"] = ci_trivy
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        st.error(
                            "❌ No published CI results found. The scan-results "
                            "branch is created by the pipeline's 'Publish Results' "
                            "job — push a commit so the pipeline runs at least once, "
                            "and make sure the repository is public."
                        )
                    else:
                        st.error(f"❌ Could not fetch CI results: HTTP {e.code}")
                except Exception as e:
                    st.error(f"❌ Could not fetch CI results: {e}")
        result_data = st.session_state.get("ci_report")
        if result_data:
            st.info(f"Showing latest CI results: **{st.session_state.get('ci_report_name', '')}**")

    elif source == "📤 Upload a file":
        # Report JSONs also come out of CI as downloadable artifacts, so accept
        # an uploaded file (e.g. clean_report.json / vulnerable_report.json from
        # the pipeline run's artifacts).
        uploaded = st.file_uploader(
            "Load a report file (e.g. downloaded from a CI pipeline run):",
            type="json",
            help="In GitHub Actions, open the run page and download the "
                 "'evaluation-reports' or 'compliance-report' artifact, unzip it, "
                 "and drop the JSON file here.",
        )
        if uploaded is not None:
            try:
                result_data = json.load(uploaded)
                st.info(f"Loaded uploaded report `{uploaded.name}`")
            except json.JSONDecodeError as e:
                st.error(f"❌ Not a valid report file: {e}")

    # Fix 2: Always guard with os.path.exists() — prevents FileNotFoundError
    # crash on a fresh clone before any scan has been run.
    elif not os.path.exists(report_path):
        st.warning(
            "⚠️ No scan report found at `reports/scan_report.json`.\n\n"
            "Run a scan first using **📂 Scan Directory** mode above, or via CLI:\n"
            "```bash\npython compliance_engine/scanner.py .\n```"
        )
    else:
        try:
            with open(report_path) as f:
                result_data = json.load(f)
            st.info(f"Loaded report from `{repo_relative(report_path)}`")
        except (json.JSONDecodeError, IOError) as e:
            st.error(f"❌ Could not read report file: {e}")

# ─── Results ───────────────────────────────────────────────────
if result_data:
    findings = result_data.get("findings", [])

    # ── Status Banner ──
    passed = result_data.get("passed", False)
    if passed:
        st.success("## ✅ BUILD PASSED — No critical or high severity issues found.")
        st.caption(
            "This code meets the security and NDPA compliance checks and is safe to release."
        )
    else:
        st.error("## ❌ BUILD FAILED — Critical or high severity issues require remediation before merge.")
        st.caption(
            "In plain terms: this code contains issues that could expose customer data or "
            "payment credentials, or breach NDPA 2023 obligations. The release is blocked "
            "until the issues below are fixed."
        )

    # ── Metric Cards ──
    m1, m2, m3, m4, m5 = st.columns(5)
    m1.metric("Files Scanned", result_data.get("files_scanned", 0))
    m2.metric("Total Findings", result_data.get("total_findings", 0))
    m3.metric("🔴 Critical", result_data.get("critical", 0))
    m4.metric("🟠 High", result_data.get("high", 0))
    m5.metric("🟡 Warnings", result_data.get("warning", 0))

# ─── Compliance Trend ──────────────────────────────────────────
# Shown in both modes, above the per-file details: stakeholders see the
# direction of travel first, then drill into individual files if needed.
# Each scan appends one summary row to reports/scan_history.json.
st.markdown("---")
st.subheader("📈 Compliance Trend")

history = []
if os.path.exists(history_path):
    try:
        with open(history_path) as f:
            history = json.load(f)
    except (json.JSONDecodeError, IOError):
        history = []

# When CI results have been fetched, the pipeline's accumulated history is
# available too — usually the one stakeholders care about.
ci_history = st.session_state.get("ci_history")
if ci_history:
    hist_source = st.radio(
        "History source:",
        ["☁️ CI pipeline", "💻 This computer"],
        horizontal=True,
        help="CI pipeline shows every scan run by GitHub Actions; "
             "This computer shows scans run from this machine.",
    )
    if hist_source == "☁️ CI pipeline":
        history = ci_history

if not history:
    st.caption(
        "No scan history yet. Every scan you run adds one point to this chart, "
        "so over time it shows whether the number of security issues is rising or falling."
    )
else:
    hist_df = pd.DataFrame(history)
    hist_df["scanned_at"] = pd.to_datetime(hist_df["scanned_at"])

    # Older history entries may hold absolute paths; scope them to the repo
    # so equivalent targets merge and the selector stays readable.
    hist_df["target"] = hist_df["target"].map(repo_relative)

    # Trends only make sense per scan target — a scan of the test corpus and a
    # scan of the real project would otherwise look like a huge spike.
    targets = list(dict.fromkeys(hist_df["target"]))
    default_ix = targets.index(hist_df.iloc[-1]["target"])
    selected_target = st.selectbox("Show history for:", targets, index=default_ix)
    tdf = hist_df[hist_df["target"] == selected_target].sort_values("scanned_at")

    # Headline: latest scan vs the one before it. Deltas use inverse colors
    # because for security issues, down is good.
    latest = tdf.iloc[-1]
    prev = tdf.iloc[-2] if len(tdf) >= 2 else None
    h1, h2, h3, h4 = st.columns(4)
    for col, label, key in (
        (h1, "🔴 Critical issues", "critical"),
        (h2, "🟠 High-risk issues", "high"),
        (h3, "🟡 Warnings", "warning"),
        (h4, "Total findings", "total_findings"),
    ):
        delta = int(latest[key] - prev[key]) if prev is not None else None
        col.metric(label, int(latest[key]), delta=delta, delta_color="inverse")
    if prev is not None:
        st.caption(
            "Change shown against the previous scan of this target — "
            "green means fewer issues than last time."
        )

    if len(tdf) >= 2:
        trend_long = (
            tdf.rename(columns={"critical": "Critical", "high": "High", "warning": "Warning"})
            .melt(
                id_vars="scanned_at",
                value_vars=["Critical", "High", "Warning"],
                var_name="Severity",
                value_name="Issues",
            )
        )
        # X-axis pips on hour boundaries. Vega's own hour-interval ticking is
        # unreliable at sub-hour data spans, so compute the tick positions here
        # and cap them at ~12 so multi-day histories don't overcrowd the axis.
        ts = pd.to_datetime(trend_long["scanned_at"])
        tick_start = ts.min().floor("h")
        tick_end = ts.max().ceil("h")
        if tick_end <= tick_start:
            tick_end = tick_start + pd.Timedelta(hours=1)
        span_hours = int((tick_end - tick_start).total_seconds() // 3600)
        step_hours = max(1, -(-span_hours // 12))
        hour_ticks = [
            alt.DateTime(year=t.year, month=t.month, date=t.day, hours=t.hour)
            for t in pd.date_range(tick_start, tick_end, freq=f"{step_hours}h")
        ]
        # Sequential severity ramp (dark → light = worst → least severe).
        # Steps validated: monotonic lightness, all >= 3:1 contrast on white.
        trend_chart = (
            alt.Chart(trend_long)
            .mark_line(strokeWidth=2, point=alt.OverlayMarkDef(size=64))
            .encode(
                x=alt.X(
                    "scanned_at:T",
                    title="Scan date & time",
                    axis=alt.Axis(
                        values=hour_ticks,
                        format="%b %d, %H:00",
                        labelAngle=0,
                    ),
                ),
                y=alt.Y("Issues:Q", title="Number of issues found"),
                color=alt.Color(
                    "Severity:N",
                    scale=alt.Scale(
                        domain=["Critical", "High", "Warning"],
                        range=["#9f1710", "#c05702", "#997400"],
                    ),
                    legend=alt.Legend(title="Severity"),
                ),
                tooltip=[
                    alt.Tooltip("scanned_at:T", title="Scan time", format="%b %d, %Y %H:%M"),
                    alt.Tooltip("Severity:N", title="Severity"),
                    alt.Tooltip("Issues:Q", title="Issues"),
                ],
            )
        )
        st.altair_chart(trend_chart, use_container_width=True)
        st.caption(
            "Each point is one scan. Lines trending down means the codebase is getting safer."
        )
    else:
        st.caption("Run this target again later to see the trend line between scans.")

    with st.expander("📋 View full scan log"):
        log_df = tdf.copy()
        log_df["Result"] = log_df["passed"].map({True: "✅ Passed", False: "❌ Failed"})
        log_df = log_df.rename(columns={
            "scanned_at": "Date & time (UTC)",
            "files_scanned": "Files checked",
            "critical": "Critical",
            "high": "High",
            "warning": "Warnings",
            "total_findings": "Total findings",
        })[["Date & time (UTC)", "Files checked", "Critical", "High", "Warnings", "Total findings", "Result"]]
        st.dataframe(log_df, use_container_width=True, hide_index=True)

# ─── Individual File Results ───────────────────────────────────
if result_data:
    st.markdown("---")

    if not findings:
        st.balloons()
        st.success("🎉 No findings detected. Your code is clean!")
    else:
        # ── Filters ──
        st.subheader("🔎 Filter Findings")
        col_sev, col_cat, col_sort = st.columns(3)
        all_severities = ["CRITICAL", "HIGH", "WARNING"]
        all_categories = sorted(set(f["category"] for f in findings))

        selected_sev = col_sev.multiselect("Severity", all_severities, default=all_severities)
        selected_cat = col_cat.multiselect("Category", all_categories, default=all_categories)
        sort_by = col_sort.selectbox(
            "Sort by",
            ["Severity (critical first)", "File name", "Scan order"],
        )

        filtered = [
            f for f in findings
            if f["severity"] in selected_sev and f["category"] in selected_cat
        ]

        SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "WARNING": 2}
        if sort_by == "Severity (critical first)":
            filtered.sort(key=lambda f: (SEVERITY_RANK.get(f["severity"], 99), f["filename"], f["line_number"]))
        elif sort_by == "File name":
            filtered.sort(key=lambda f: (f["filename"], f["line_number"]))
        # "Scan order" keeps the original order from the report

        # ── Findings Table ──
        st.subheader(f"📋 Findings ({len(filtered)} shown)")
        SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "WARNING": "🟡"}

        for finding in filtered:
            icon = SEVERITY_ICON.get(finding["severity"], "⚪")
            shown_file = repo_relative(finding["filename"])
            with st.expander(
                f"{icon} [{finding['severity']}] {finding['rule_id']} — {finding['name']} | `{shown_file}:{finding['line_number']}`"
            ):
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown(f"**Category:** `{finding['category'].upper()}`")
                    st.markdown(f"**File:** `{shown_file}`")
                    st.markdown(f"**Line:** {finding['line_number']}")
                    st.code(finding["line_content"], language="text")
                with c2:
                    st.markdown(f"**Description:**\n{finding['description']}")
                    st.info(f"🔧 **Remediation:** {finding['remediation']}")

        # ── Findings by Category ──
        st.markdown("---")
        st.subheader("📊 Findings by Category")
        CATEGORY_LABELS = {
            "secret": "Hardcoded secrets",
            "pii": "Personal data (PII)",
            "ndpa": "NDPA / data sovereignty",
            "container": "Container security",
        }
        category_counts = {}
        for f in findings:
            label = CATEGORY_LABELS.get(f["category"], f["category"])
            category_counts[label] = category_counts.get(label, 0) + 1

        cat_df = pd.DataFrame(
            {"Category": list(category_counts), "Findings": list(category_counts.values())}
        )
        cat_chart = (
            alt.Chart(cat_df)
            .mark_bar(color="#446e9b", cornerRadiusTopRight=4, cornerRadiusBottomRight=4)
            .encode(
                x=alt.X("Findings:Q", title="Number of findings"),
                y=alt.Y("Category:N", title="Issue category", sort="-x"),
                tooltip=[
                    alt.Tooltip("Category:N", title="Category"),
                    alt.Tooltip("Findings:Q", title="Findings"),
                ],
            )
        )
        st.altair_chart(cat_chart, use_container_width=True)

    # ── Scan Metadata ──
    st.markdown("---")
    st.caption(f"Scan timestamp: {result_data.get('scanned_at', 'N/A')} UTC")

# ─── Trivy: Infrastructure & Container Scan ────────────────────
# Second, independent scanner run by the CI pipeline. Shown whenever CI
# results have been fetched, so stakeholders see the full security picture
# without reading pipeline logs.
ci_trivy = st.session_state.get("ci_trivy") or {}
if ci_trivy:
    TRIVY_EXPECTATION = {
        "Docker image (known CVEs)":
            "The application container, checked against the global vulnerability "
            "database. Anything listed here is a known, published weakness.",
        "Vulnerable corpus (infrastructure)":
            "Deliberately insecure test files — findings here are EXPECTED and "
            "prove the pipeline catches cloud misconfigurations.",
        "Clean corpus (infrastructure)":
            "Well-configured test files — this list should be empty.",
    }
    st.markdown("---")
    st.subheader("🐳 Infrastructure & Container Scan (Trivy)")
    st.caption(
        "Results from Trivy, the pipeline's second scanner: it checks the Docker "
        "image for known vulnerabilities (CVEs) and infrastructure files for "
        "insecure cloud configurations."
    )
    for tab, label in zip(st.tabs(list(ci_trivy)), ci_trivy):
        with tab:
            st.caption(TRIVY_EXPECTATION.get(label, ""))
            counts, rows = summarize_trivy(ci_trivy[label])
            t1, t2, t3 = st.columns(3)
            t1.metric("🔴 Critical", counts.get("CRITICAL", 0))
            t2.metric("🟠 High", counts.get("HIGH", 0))
            t3.metric("Total issues", len(rows))
            if rows:
                st.dataframe(
                    pd.DataFrame(rows),
                    use_container_width=True,
                    hide_index=True,
                )
            else:
                st.success("✅ No issues found in this scan.")
