import argparse
import os
import re
import socket
import subprocess
import sys
import time
from collections import Counter
from datetime import date

from dotenv import load_dotenv

from ai_audit import GeminiAuditor
from scanner import clone_and_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a Git repository for security risks and audit using Gemini.")

    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run terminal scan/audit mode")
    scan_parser.add_argument(
        "repo_url",
        nargs="?",
        default="thisdir",
        help="Git repository URL, local path, or 'thisdir' (default: current directory)",
    )
    scan_parser.add_argument("--max-files", type=int, default=0, help="Maximum files to audit (0 = all)")
    scan_parser.add_argument("--no-ai", action="store_true", help="Run scanner only without Gemini audit")
    scan_parser.add_argument("--md", action="store_true", help="Emit readable Markdown report to stdout")

    subparsers.add_parser("ui", help="Launch Streamlit dashboard")

    return parser


def run_scan(args: argparse.Namespace) -> int:
    source_ref = (args.repo_url or "thisdir").strip() or "thisdir"

    def _find_available_port(preferred: int = 8501) -> int:
        def _is_free(port: int) -> bool:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                return sock.connect_ex(("127.0.0.1", port)) != 0

        if _is_free(preferred):
            return preferred

        for port in range(preferred + 1, preferred + 20):
            if _is_free(port):
                return port

        # Fall back to an OS-assigned free port.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    def _start_streamlit_background(report_path: str) -> None:
        ui_port = _find_available_port(8501)
        app_path = os.path.join(os.path.dirname(__file__), "streamlit_app.py")
        cmd = [
            sys.executable,
            "-m",
            "streamlit",
            "run",
            app_path,
            "--server.port",
            str(ui_port),
            "--",
            "--report-file",
            report_path,
            "--repo-url",
            source_ref,
        ]

        popen_kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if os.name == "nt":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP

        try:
            subprocess.Popen(cmd, **popen_kwargs)
            print("Launching Streamlit dashboard...")
            print(f"Dashboard URL: http://localhost:{ui_port}")
        except Exception as exc:
            print(f"Could not auto-start Streamlit UI: {exc}", file=sys.stderr)

    def _clone_label(path: str) -> str:
        return os.path.basename(path.rstrip("/\\"))

    def _escape_md(value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ").strip()

    def _build_markdown_report(findings: list, audits: list[dict], clone_path: str) -> str:
        def _severity(reason: str) -> tuple[str, str]:
            text = reason.lower()
            if any(k in text for k in ["hardcoded credential", "jwt token", "aws access key", "aws secret key"]):
                return "Critical", "🔴"

            if "high-entropy" in text:
                match = re.search(r"entropy=([0-9]+(?:\.[0-9]+)?)", text)
                if match and float(match.group(1)) >= 5.8:
                    return "Critical", "🔴"
                return "High", "🟠"

            if "ast: dangerous logic" in text:
                return "High", "🟠"

            return "Medium", "🟡"

        def _short_reason(reason: str) -> str:
            text = reason.lower()
            if "hardcoded credential" in text:
                return "Hardcoded credential pattern detected"
            if "high-entropy" in text:
                return "High entropy string"
            if "unpinned npm dependency" in text or "unpinned python dependency" in text:
                return "Unpinned dependency"
            if "ast: dangerous logic" in text:
                return "Dangerous logic pattern"
            return reason

        def _audit_summary_text(item: dict) -> str:
            if item.get("error"):
                return f"Audit failed: {item['error']}"
            result_text = (item.get("result") or "").strip()
            if not result_text:
                return "No AI response returned."
            first_line = result_text.splitlines()[0].strip()
            return first_line or "AI response received."

        critical_findings = []
        high_findings = []
        medium_findings = []

        for task in findings:
            sev, sev_icon = _severity(task.reason)
            record = {
                "file": os.path.basename(task.file_path),
                "reason": task.reason,
                "short_reason": _short_reason(task.reason),
                "severity": sev,
                "severity_icon": sev_icon,
                "language": task.language,
            }
            if sev == "Critical":
                critical_findings.append(record)
            elif sev == "High":
                high_findings.append(record)
            else:
                medium_findings.append(record)

        dep_examples: list[str] = []
        for task in findings:
            if "Unpinned npm dependency" in task.reason:
                _, _, pkg = task.reason.partition(":")
                pkg = pkg.strip()
                if pkg and pkg not in dep_examples:
                    dep_examples.append(pkg)
            if len(dep_examples) >= 3:
                break

        lines = [
            "# 🛡️ Repo Shield Security Report",
            "",
            f"**Repository:** {source_ref}  ",
            f"**Scan Time:** {date.today().isoformat()}  ",
            f"**Total Findings:** {len(findings)}  ",
            "",
            "---",
            "",
            "## 📊 Executive Summary",
            "",
            f"This repository contains **{len(findings)} potential security issues**, including:",
            "",
            f"- 🔴 {len(critical_findings)} Critical Issues (possible secrets / credentials)",
            f"- 🟠 {len(high_findings)} High Risk Issues (unsafe patterns)",
            f"- 🟡 {len(medium_findings)} Medium Risk Issues (dependency risks)",
            "",
            "👉 Immediate attention is required for **credential exposure and secret leakage**.",
            "",
            "---",
            "",
            "## 📈 Risk Breakdown",
            "",
            "| Severity  | Count |",
            "|----------|------:|",
            f"| 🔴 Critical | {len(critical_findings)} |",
            f"| 🟠 High     | {len(high_findings)} |",
            f"| 🟡 Medium   | {len(medium_findings)} |",
            "",
            "---",
            "",
            "## 🚨 Critical Issues",
            "",
        ]

        if critical_findings:
            for idx, finding in enumerate(critical_findings, 1):
                lines.extend([
                    f"### {idx}. {finding['short_reason']}",
                    f"- **File:** {_escape_md(finding['file'])}",
                    f"- **Reason:** {_escape_md(finding['reason'])}",
                    "",
                    "---",
                    "",
                ])
        else:
            lines.extend(["No critical issues found.", "", "---", ""])

        lines.extend(["## ⚠️ High Risk Issues", "", "### Unsafe Pattern Usage", ""])
        if high_findings:
            for finding in high_findings[:10]:
                lines.extend([
                    f"- **File:** {_escape_md(finding['file'])}",
                    f"- **Reason:** {_escape_md(finding['reason'])}",
                    "",
                ])
        else:
            lines.append("No high risk issues found.")
            lines.append("")

        lines.extend(["---", "", "## 📦 Dependency Risks (Aggregated)", ""])
        dep_count = sum(1 for t in findings if "Unpinned" in t.reason)
        lines.append(f"⚠️ Found **{dep_count}+ unpinned dependencies**")
        lines.append("")
        if dep_examples:
            lines.append("Example:")
            lines.append("")
            for example in dep_examples:
                lines.append(f"- {_escape_md(example)}")
            lines.append("")
        lines.extend([
            "👉 Risk:",
            "- Unexpected breaking changes",
            "- Supply chain attacks",
            "",
            "---",
            "",
            "## 📋 Detailed Findings",
            "",
            "| # | File | Severity | Reason |",
            "|---|------|----------|--------|",
        ])

        for idx, task in enumerate(findings, 1):
            sev, sev_icon = _severity(task.reason)
            lines.append(
                f"| {idx} | {_escape_md(os.path.basename(task.file_path))} | {sev_icon} {sev} | {_escape_md(_short_reason(task.reason))} |"
            )

        lines.extend([
            "",
            "---",
            "",
            "## 🤖 AI Audit",
            "",
        ])

        if audits:
            success_count = sum(1 for item in audits if item.get("result") and not item.get("error"))
            failed_count = sum(1 for item in audits if item.get("error"))
            lines.extend([
                f"- Files sent to AI audit: **{len(audits)}**",
                f"- Successful AI responses: **{success_count}**",
                f"- Failed AI audits: **{failed_count}**",
                "",
                "| # | File | Status | AI Summary |",
                "|---|------|--------|------------|",
            ])
            for idx, item in enumerate(audits, 1):
                status = "❌ Failed" if item.get("error") else "✅ Success"
                lines.append(
                    f"| {idx} | {_escape_md(os.path.basename(item['file_path']))} | {status} | {_escape_md(_audit_summary_text(item))} |"
                )
        else:
            lines.append("AI audit was not executed for this run (scanner-only mode or no files selected).")

        lines.extend([
            "",
            "---",
            "",
            "## ✅ Tips",
            "",
            "### 🔴 Critical Fixes",
            "- Remove hardcoded credentials immediately  ",
            "- Rotate exposed secrets  ",
            "",
            "### 🟠 High Priority",
            "- Review suspicious entropy-based strings  ",
            "- Audit sensitive files manually  ",
            "",
            "### 🟡 Medium Priority",
            "- Pin dependency versions  ",
            "- Use lockfiles properly  ",
            "",
            "---",
            "",
            "## ⚙️ Generated by Repo Shield",
        ])

        return "\n".join(lines)

    def _log(message: str) -> None:
        if args.md:
            print(message, file=sys.stderr)
        else:
            print(message)

    def _write_default_report(findings: list, audits: list[dict], clone_path: str) -> str:
        report_text = _build_markdown_report(findings, audits, clone_path)
        report_path = os.path.join(os.getcwd(), "report.md")
        with open(report_path, "w", encoding="utf-8") as handle:
            handle.write(report_text)
        _log(f"Markdown report saved: {report_path}")
        return report_path

    if source_ref.lower() == "thisdir":
        _log("Copying and scanning current directory (thisdir)")
    else:
        _log(f"Cloning/copying and scanning: {source_ref}")

    clone_path, tasks, tmp_dir = clone_and_scan(source_ref)
    clone_name = _clone_label(clone_path)

    audit_results: list[dict] = []
    try:
        _log(f"Cloned to: {clone_name}")
        _log(f"High-risk findings: {len(tasks)}")

        if not tasks:
            report_path = _write_default_report([], [], clone_path)
            _start_streamlit_background(report_path)
            if args.md:
                print(_build_markdown_report([], [], clone_path))
            else:
                _log("No high-risk findings.")
            return 0

        for index, task in enumerate(tasks, 1):
            _log(f"{index:03d}. {task.reason} -> {os.path.basename(task.file_path)}")

        if args.no_ai:
            report_path = _write_default_report(tasks, [], clone_path)
            _start_streamlit_background(report_path)
            if args.md:
                print(_build_markdown_report(tasks, [], clone_path))
            return 0

        try:
            auditor = GeminiAuditor(api_key=os.getenv("GOOGLE_API_KEY"))
        except ValueError as exc:
            _log(str(exc))
            return 1

        selected = tasks
        if args.max_files > 0:
            selected = tasks[: args.max_files]

        for idx, task in enumerate(selected, 1):
            _log(f"\nAuditing {idx}/{len(selected)}: {os.path.basename(task.file_path)}")
            try:
                with open(task.file_path, "r", encoding="utf-8", errors="ignore") as handle:
                    code = handle.read()
                result = auditor.audit_code(task, code)
                audit_results.append(
                    {
                        "file_path": task.file_path,
                        "reason": task.reason,
                        "language": task.language,
                        "result": result,
                    }
                )
                _log(result)
            except Exception as exc:
                error_text = f"Audit failed for {os.path.basename(task.file_path)}: {exc}"
                audit_results.append(
                    {
                        "file_path": task.file_path,
                        "reason": task.reason,
                        "language": task.language,
                        "error": str(exc),
                    }
                )
                _log(error_text)

            if idx % 5 == 0 and idx < len(selected):
                _log("Reached 5 requests. Waiting 60 seconds to avoid quota limits...")
                time.sleep(60)

        if args.md:
            print(_build_markdown_report(tasks, audit_results, clone_path))

        report_path = _write_default_report(tasks, audit_results, clone_path)
        _start_streamlit_background(report_path)

        return 0
    finally:
        tmp_dir.cleanup()


def run_ui() -> int:
    app_path = os.path.join(os.path.dirname(__file__), "streamlit_app.py")
    print("Launching Streamlit dashboard...")
    return subprocess.call([sys.executable, "-m", "streamlit", "run", app_path])


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    load_dotenv()
    args = build_parser().parse_args()

    if args.command == "scan":
        return run_scan(args)
    if args.command == "ui":
        return run_ui()

    print("Unknown command. Use 'scan' or 'ui'.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
