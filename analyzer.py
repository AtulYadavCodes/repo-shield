import ast
import json
import math
import os
import re
from typing import List

from models import AuditTask

HARD_CODED_CRED_PATTERN = re.compile(
    r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key|client[_-]?secret)\s*[:=]\s*['\"][^'\"\n]{4,}['\"]"
)
JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
AWS_ACCESS_KEY_PATTERN = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
AWS_SECRET_KEY_PATTERN = re.compile(
    r"(?i)(?:aws(.{0,20})?(secret|session)?(.{0,20})?key)\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]"
)
ENTROPY_CANDIDATE_PATTERN = re.compile(r"['\"]([A-Za-z0-9_\-+/=]{20,120})['\"]")


SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__"}


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    probabilities = [text.count(ch) / len(text) for ch in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)


def _has_mixed_charset(value: str) -> bool:
    has_lower = any(ch.islower() for ch in value)
    has_upper = any(ch.isupper() for ch in value)
    has_digit = any(ch.isdigit() for ch in value)
    return (has_lower and has_upper) or (has_lower and has_digit) or (has_upper and has_digit)


def _detect_entropy_secret(content: str) -> str | None:
    for match in ENTROPY_CANDIDATE_PATTERN.finditer(content):
        candidate = match.group(1)
        if candidate.startswith(("http://", "https://")):
            continue
        if not _has_mixed_charset(candidate):
            continue
        entropy = _shannon_entropy(candidate)
        if entropy >= 4.3:
            return f"High-entropy secret-like string detected (entropy={entropy:.2f})"
    return None


def _add_hit(hit_list: List[AuditTask], seen: set[tuple[str, str]], file_path: str, reason: str, language: str) -> None:
    key = (file_path, reason)
    if key not in seen:
        hit_list.append(AuditTask(file_path=file_path, reason=reason, language=language))
        seen.add(key)


def _scan_dependency_manifest(
    path: str,
    file_name: str,
    content: str,
    hit_list: List[AuditTask],
    seen: set[tuple[str, str]],
) -> None:
    if file_name == "requirements.txt":
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("-r", "--", "git+", "http://", "https://")):
                _add_hit(hit_list, seen, path, "requirements.txt uses indirect/external source dependency", "txt")
                continue
            if "==" not in line:
                _add_hit(hit_list, seen, path, f"Unpinned Python dependency: {line}", "txt")

    if file_name == "package.json":
        try:
            pkg = json.loads(content)
        except Exception:
            _add_hit(hit_list, seen, path, "Invalid package.json format", "json")
            return

        for section in ["dependencies", "devDependencies"]:
            deps = pkg.get(section, {})
            if not isinstance(deps, dict):
                continue
            for dep_name, version in deps.items():
                version_str = str(version).strip()
                if version_str in {"*", "latest"} or version_str.startswith(("^", "~", ">", "<")):
                    _add_hit(
                        hit_list,
                        seen,
                        path,
                        f"Unpinned npm dependency in {section}: {dep_name}@{version_str}",
                        "json",
                    )

        scripts = pkg.get("scripts", {})
        if isinstance(scripts, dict) and any(k in scripts for k in ["preinstall", "install", "postinstall"]):
            _add_hit(hit_list, seen, path, "Install-time scripts present in package.json", "json")


def get_high_risk_files(directory: str) -> List[AuditTask]:
    hit_list: List[AuditTask] = []
    seen_hits: set[tuple[str, str]] = set()

    for root, _, files in os.walk(directory):
        if any(skip in root for skip in SKIP_DIRS):
            continue

        for file_name in files:
            path = os.path.join(root, file_name)
            ext = file_name.split(".")[-1] if "." in file_name else "txt"

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                    content = handle.read()

                if file_name in ["requirements.txt", "package.json"]:
                    _scan_dependency_manifest(path, file_name, content, hit_list, seen_hits)

                if HARD_CODED_CRED_PATTERN.search(content):
                    _add_hit(hit_list, seen_hits, path, "Hardcoded credential pattern", ext)
                if JWT_PATTERN.search(content):
                    _add_hit(hit_list, seen_hits, path, "JWT token pattern detected", ext)
                if AWS_ACCESS_KEY_PATTERN.search(content):
                    _add_hit(hit_list, seen_hits, path, "AWS Access Key ID pattern detected", ext)
                if AWS_SECRET_KEY_PATTERN.search(content):
                    _add_hit(hit_list, seen_hits, path, "AWS Secret Key pattern detected", ext)

                entropy_reason = _detect_entropy_secret(content)
                if entropy_reason:
                    _add_hit(hit_list, seen_hits, path, entropy_reason, ext)

                if file_name.endswith(".py"):
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ["eval", "exec"]:
                            _add_hit(hit_list, seen_hits, path, "AST: Dangerous Logic", "python")
                            break
            except Exception:
                continue

    return hit_list
