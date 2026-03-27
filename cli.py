import argparse
import os
import re
import sys

from dotenv import load_dotenv

from ai_audit import GeminiAuditor
from models import AuditTask
from scanner import clone_and_scan

MANIFEST_LOCK = {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scan a Git repository for security risks and audit using Gemini.")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run terminal scan/audit mode")
    scan.add_argument("repo_url", nargs="?", default="thisdir", help="Repo URL/path or 'thisdir'")
    scan.add_argument("--max-files", type=int, default=0, help="Max files to AI audit (0 = all)")
    scan.add_argument("--no-ai", action="store_true", help="Run scanner only")
    return parser


def _confidence(value: object) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.0


def _severity(reason: str) -> str:
    text = reason.lower()
    if any(k in text for k in ["hardcoded credential", "jwt token", "aws access key", "aws secret key"]):
        return "critical"
    if "high-entropy" in text:
        m = re.search(r"entropy=([0-9]+(?:\.[0-9]+)?)", text)
        return "critical" if m and float(m.group(1)) >= 5.8 else "high"
    return "high" if "ast: dangerous logic" in text else "medium"


def _short_reason(reason: str) -> str:
    text = reason.lower()
    if "hardcoded credential" in text:
        return "hardcoded credential pattern"
    if "high-entropy" in text:
        return "high entropy string"
    if "unpinned npm dependency" in text or "unpinned python dependency" in text:
        return "unpinned dependency"
    if "ast: dangerous logic" in text:
        return "dangerous logic pattern"
    return reason


def _is_regex_signal(reason: str) -> bool:
    text = reason.lower()
    return any(
        k in text
        for k in [
            "hardcoded credential pattern",
            "jwt token pattern detected",
            "aws access key id pattern detected",
            "aws secret key pattern detected",
        ]
    )


def _audit_line(item: dict) -> str:
    if item.get("error"):
        e = str(item.get("error") or "")
        return "quota/rate-limit exceeded" if any(k in e.lower() for k in ["429", "resource_exhausted", "quota"]) else f"failed: {e}"

    result = item.get("result") or {}
    if not isinstance(result, dict):
        return "no AI response"
    verdict = "vulnerability" if result.get("is_vulnerability") else "no vulnerability"
    return f"{verdict} ({_confidence(result.get('confidence', 0)):.2f}) type={result.get('type', 'unknown')}"


def _print_report(source_ref: str, findings: list[AuditTask], audits: list[dict]) -> None:
    counts = {"critical": 0, "high": 0, "medium": 0}
    for t in findings:
        counts[_severity(t.reason)] += 1

    print("\n" + "=" * 72)
    print("REPO SHIELD TERMINAL REPORT")
    print("=" * 72)
    print(f"Repository: {source_ref}")
    print(f"Total findings (static): {len(findings)}")
    print(f"Severity breakdown: critical={counts['critical']} high={counts['high']} medium={counts['medium']}")

    real_issues = []
    false_positives = []

    for item in audits:
        if item.get("error"):
            continue
        result = item.get("result") or {}
        if not isinstance(result, dict):
            continue

        if bool(result.get("is_vulnerability")) and _is_regex_signal(str(item.get("reason") or "")):
            real_issues.append(
                {
                    "file": os.path.basename(str(item.get("file_path") or "")),
                    "type": str(result.get("type") or "unknown"),
                    "confidence": _confidence(result.get("confidence", 0)),
                    "fix": str(result.get("fix") or "No fix provided"),
                }
            )
        elif not bool(result.get("is_vulnerability")):
            false_positives.append(
                {
                    "file": os.path.basename(str(item.get("file_path") or "")),
                    "reason": _short_reason(str(item.get("reason") or "")),
                    "confidence": _confidence(result.get("confidence", 0)),
                    "type": str(result.get("type") or "unknown"),
                }
            )

    print(f"Real issues (regex + AI confirmed): {len(real_issues)}")
    for i, issue in enumerate(real_issues, 1):
        print(f"  {i}. file={issue['file']} type={issue['type']} confidence={issue['confidence']:.2f}")
        print(f"     fix: {issue['fix']}")

    print("\nDetailed findings:")
    if not findings:
        print("  none")
    else:
        for i, t in enumerate(findings, 1):
            print(f"  {i}. [{_severity(t.reason)}] {os.path.basename(t.file_path)} - {_short_reason(t.reason)}")

    print("\nAI audit summary:")
    if not audits:
        print("  not executed")
    else:
        success = sum(1 for x in audits if x.get("result") and not x.get("error"))
        failed = sum(1 for x in audits if x.get("error"))
        print(f"  files audited={len(audits)} success={success} failed={failed}")
        for i, item in enumerate(audits, 1):
            print(f"  {i}. {os.path.basename(str(item.get('file_path') or ''))}: {_audit_line(item)}")

        print("\nFalse positives (AI says no vulnerability):")
        if not false_positives:
            print("  none")
        else:
            for i, fp in enumerate(false_positives, 1):
                print(f"  {i}. {fp['file']} reason={fp['reason']} confidence={fp['confidence']:.2f} type={fp['type']}")

    print("=" * 72 + "\n")


def run_scan(args: argparse.Namespace) -> int:
    source_ref = (args.repo_url or "thisdir").strip() or "thisdir"
    print("Starting scan: current directory (thisdir)" if source_ref.lower() == "thisdir" else f"Starting scan: {source_ref}")

    clone_path, tasks, tmp_dir = clone_and_scan(source_ref)
    try:
        print(f"Repository prepared as: {os.path.basename(clone_path.rstrip('/\\'))}")
        print(f"Scanner/AST findings detected: {len(tasks)}")

        if not tasks:
            _print_report(source_ref, [], [])
            print("Scan complete: no high-risk findings.")
            return 0

        if args.no_ai:
            _print_report(source_ref, tasks, [])
            print("Scan complete (scanner only).")
            return 0

        try:
            auditor = GeminiAuditor(api_key=os.getenv("GOOGLE_API_KEY"))
        except ValueError as exc:
            print(str(exc))
            return 1

        def eligible(task: AuditTask) -> bool:
            base = os.path.basename(task.file_path)
            if base not in MANIFEST_LOCK:
                return True
            reason = task.reason.lower()
            return any(k in reason for k in ["hardcoded credential", "jwt token", "aws access key", "aws secret key", "high-entropy"])

        ai_candidates = [t for t in tasks if eligible(t)]
        if args.max_files > 0:
            ai_candidates = ai_candidates[: args.max_files]

        if not ai_candidates:
            print("No eligible files for AI audit (only low-risk manifests/lockfiles found).")
            _print_report(source_ref, tasks, [])
            print("Scan complete (scanner only: no AI-eligible files).")
            return 0

        print(f"Running AI audit on {len(ai_candidates)} files...")
        audits = []
        for task in ai_candidates:
            try:
                with open(task.file_path, "r", encoding="utf-8", errors="ignore") as handle:
                    code = handle.read()
                audits.append(
                    {
                        "file_path": task.file_path,
                        "reason": task.reason,
                        "language": task.language,
                        "result": auditor.audit_code(task, code),
                    }
                )
            except Exception as exc:
                audits.append(
                    {
                        "file_path": task.file_path,
                        "reason": task.reason,
                        "language": task.language,
                        "error": str(exc),
                    }
                )
                print(f"AI audit error on {os.path.basename(task.file_path)}: {exc}")

        _print_report(source_ref, tasks, audits)
        print("Scan complete (scanner + AI).")
        return 0
    finally:
        tmp_dir.cleanup()


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    load_dotenv()
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        return run_scan(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
