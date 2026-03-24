import os
import shutil
import tempfile
from typing import List, Tuple

import git

from analyzer import get_high_risk_files
from models import AuditTask


def clone_repository(repo_url: str, destination: str) -> str:
    repo_name = repo_url.rstrip("/").split("/")[-1]
    if repo_name.endswith(".git"):
        repo_name = repo_name[:-4]
    if not repo_name:
        repo_name = "target_repo"

    clone_path = os.path.join(destination, repo_name)
    git.Repo.clone_from(repo_url, clone_path)
    return clone_path


def copy_local_repository(source_path: str, destination: str) -> str:
    abs_source = os.path.abspath(source_path)
    repo_name = os.path.basename(abs_source.rstrip("/\\")) or "current_dir"
    copy_path = os.path.join(destination, repo_name)
    shutil.copytree(
        abs_source,
        copy_path,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "node_modules"),
    )
    return copy_path


def prepare_repository(source: str, destination: str) -> str:
    normalized = (source or "").strip()
    if not normalized or normalized.lower() == "thisdir":
        return copy_local_repository(os.getcwd(), destination)

    if os.path.exists(normalized):
        return copy_local_repository(normalized, destination)

    return clone_repository(normalized, destination)


def clone_and_scan(source: str) -> Tuple[str, List[AuditTask], tempfile.TemporaryDirectory]:
    tmp_dir = tempfile.TemporaryDirectory()
    clone_path = prepare_repository(source, tmp_dir.name)
    tasks = get_high_risk_files(clone_path)
    return clone_path, tasks, tmp_dir
