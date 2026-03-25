import argparse
import os
import re

import pandas as pd
import plotly.express as px
import streamlit as st


def _parse_cli_report_file() -> str:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo-url", default="")
    parser.add_argument("--report-file", default="")
    args, _ = parser.parse_known_args()
    return args.report_file


def _load_findings_from_report(report_text: str) -> pd.DataFrame:
    lines = report_text.splitlines()

    header_idx = None
    divider_idx = None
    for idx, line in enumerate(lines):
        if line.strip() in (
            "| # | File | Severity | Reason |",
            "| # | File | Severity (pre-AI) | Reason |",
        ):
            header_idx = idx
        if header_idx is not None and idx == header_idx + 1 and line.strip().startswith("|---"):
            divider_idx = idx
            break

    if divider_idx is None:
        return pd.DataFrame(columns=["File", "Severity", "Reason"])

    rows = []
    for raw in lines[divider_idx + 1 :]:
        line = raw.strip()
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 4:
            continue
        rows.append(
            {
                "File": cells[1],
                "Severity": cells[2],
                "Reason": cells[3],
            }
        )

    if not rows:
        return pd.DataFrame(columns=["File", "Severity", "Reason"])
    return pd.DataFrame(rows)


def _load_risk_breakdown_from_report(report_text: str) -> pd.DataFrame:
    lines = report_text.splitlines()

    header_idx = None
    divider_idx = None
    for idx, line in enumerate(lines):
        if line.strip() in (
            "| Severity  | Count |",
            "| Severity (pre-AI) | Count |",
        ):
            header_idx = idx
        if header_idx is not None and idx == header_idx + 1 and line.strip().startswith("|---"):
            divider_idx = idx
            break

    if divider_idx is None:
        return pd.DataFrame(columns=["Severity", "Count"])

    rows = []
    for raw in lines[divider_idx + 1 :]:
        line = raw.strip()
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 2:
            continue

        sev_text = cells[0]
        count_text = cells[1]
        match = re.search(r"\d+", count_text)
        if not match:
            continue

        rows.append(
            {
                "Severity": sev_text,
                "Count": int(match.group(0)),
            }
        )

    if not rows:
        return pd.DataFrame(columns=["Severity", "Count"])
    return pd.DataFrame(rows)


def _render_report_dashboard(report_path: str) -> None:
    if not os.path.exists(report_path):
        st.warning(f"Report file not found: {report_path}")
        return

    with open(report_path, "r", encoding="utf-8", errors="ignore") as handle:
        report_text = handle.read()

    st.success(f"Loaded report: {os.path.basename(report_path)}")
    # Guide users to use Streamlit's built-in print option for PDF export.
    st.caption(
        "Tip: click the ⋮ (three dots) menu in the top-right of the Streamlit app, "
        "choose 'Print', then use your browser's 'Save as PDF' option."
    )

    st.markdown(report_text)

    risk_df = _load_risk_breakdown_from_report(report_text)
    findings_df = _load_findings_from_report(report_text)
    if risk_df.empty and findings_df.empty:
        st.info("No chartable data found in report.")
        return

    st.subheader("📊 Charts From Report")
    if not risk_df.empty:
        c1, c2 = st.columns(2)
        with c1:
            fig_risk_pie = px.pie(
                values=risk_df["Count"],
                names=risk_df["Severity"],
                title="Risk Breakdown",
                hole=0.3,
            )
            st.plotly_chart(fig_risk_pie, use_container_width=True)
        with c2:
            fig_risk_bar = px.bar(
                risk_df,
                x="Severity",
                y="Count",
                title="Risk Counts by Severity",
                color="Severity",
            )
            st.plotly_chart(fig_risk_bar, use_container_width=True)

    if findings_df.empty:
        st.info("Detailed findings table is empty in this report.")
        return

    c3, c4 = st.columns(2)
    with c3:
        reason_counts = findings_df["Reason"].value_counts().head(15)
        fig_reason = px.bar(
            x=reason_counts.index,
            y=reason_counts.values,
            title="Top Finding Reasons",
            labels={"x": "Reason", "y": "Count"},
            color=reason_counts.values,
            color_continuous_scale="Reds",
        )
        st.plotly_chart(fig_reason, use_container_width=True)

    with c4:
        lang_series = findings_df["File"].str.rsplit(".", n=1).str[-1].fillna("unknown")
        lang_counts = lang_series.value_counts()
        fig_lang = px.bar(
            x=lang_counts.index,
            y=lang_counts.values,
            title="Findings by File Extension",
            labels={"x": "Extension", "y": "Count"},
            color=lang_counts.values,
            color_continuous_scale="Blues",
        )
        st.plotly_chart(fig_lang, use_container_width=True)


def main() -> None:
    st.set_page_config(page_title="Repo Shield", page_icon="🛡️", layout="wide")
    st.title("🛡️ Repo Shield Dashboard")

    report_file = _parse_cli_report_file()

    if report_file:
        _render_report_dashboard(report_file)
        return

    st.info("Report-only mode is enabled. Run a scan from CLI first, then open UI through that command.")
    st.code("repo-shield scan <repo-url>")


if __name__ == "__main__":
    main()
