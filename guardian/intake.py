"""Safe, static-only intake for approved public GitHub repositories.

This module never installs dependencies, initializes submodules, or executes
repository-provided hooks.  Canonical output models are imported from
``guardian.schemas`` at call time so C remains the sole schema owner.
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit, urlunsplit

if TYPE_CHECKING:
    from guardian.schemas import ScanMetadata


_GITHUB_HOST = "github.com"
_REPO_PART = re.compile(r"^[A-Za-z0-9_.-]+$")
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_MAX_FILES = 50_000
_MAX_BYTES = 512 * 1024 * 1024
_GIT_TIMEOUT_SECONDS = 120


class IntakeError(RuntimeError):
    """An explicit, redacted repository-intake failure."""


def _schemas() -> tuple[type[Any], type[Any]]:
    try:
        from guardian.schemas import RunStatus, ScanMetadata
    except (ImportError, ModuleNotFoundError) as exc:
        raise IntakeError(
            "guardian.schemas is unavailable; C's canonical contract must be merged"
        ) from exc
    return ScanMetadata, RunStatus


def normalize_repo_url(repo_url: str) -> str:
    """Return a canonical public GitHub HTTPS URL or reject it."""
    if not isinstance(repo_url, str) or not repo_url.strip():
        raise IntakeError("repository URL is required")
    if len(repo_url) > 2048 or any(c in repo_url for c in "\r\n\x00"):
        raise IntakeError("repository URL is malformed")
    parsed = urlsplit(repo_url.strip())
    if parsed.scheme.lower() != "https":
        raise IntakeError("only HTTPS GitHub repository URLs are allowed")
    if parsed.username or parsed.password:
        raise IntakeError("credentials in repository URLs are forbidden")
    if (parsed.hostname or "").lower() != _GITHUB_HOST or parsed.port not in (None, 443):
        raise IntakeError("only public github.com repositories are allowed")
    if parsed.query or parsed.fragment:
        raise IntakeError("repository URL query strings and fragments are forbidden")

    decoded_path = unquote(parsed.path)
    if decoded_path != parsed.path or "\\" in decoded_path:
        raise IntakeError("encoded or backslash repository paths are forbidden")
    parts = [part for part in decoded_path.split("/") if part]
    if len(parts) != 2:
        raise IntakeError("repository URL must contain exactly owner/repository")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or not _REPO_PART.fullmatch(owner) or not _REPO_PART.fullmatch(repo):
        raise IntakeError("repository owner or name is invalid")
    if owner in {".", ".."} or repo in {".", ".."}:
        raise IntakeError("repository path traversal is forbidden")
    return urlunsplit(("https", _GITHUB_HOST, f"/{owner}/{repo}.git", "", ""))


def _safe_ref(ref: str | None) -> str:
    if ref is None or ref == "":
        return "HEAD"
    if len(ref) > 255 or ref.startswith("-") or any(c in ref for c in "\r\n\x00 "):
        raise IntakeError("Git ref is malformed")
    if ".." in ref or "@{" in ref or ref.endswith((".", "/")) or "//" in ref:
        raise IntakeError("Git ref is unsafe")
    return ref


def _run_git(argv: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "",
        "GIT_SSH_COMMAND": "ssh -oBatchMode=yes",
    }
    command = [
        "git",
        "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
        "-c", "protocol.file.allow=never",
        "-c", "protocol.ext.allow=never",
        "-c", "http.followRedirects=false",
        *argv,
    ]
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise IntakeError(f"Git operation failed: {type(exc).__name__}") from exc


def _git_version() -> str:
    result = _run_git(["--version"])
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def _inspect_snapshot(repo_dir: Path) -> str:
    digest = hashlib.sha256()
    file_count = 0
    byte_count = 0
    root = repo_dir.resolve(strict=True)
    for path in sorted(repo_dir.rglob("*"), key=lambda p: p.as_posix()):
        if ".git" in path.relative_to(repo_dir).parts:
            continue
        file_count += 1
        if file_count > _MAX_FILES:
            raise IntakeError("repository exceeds maximum file count")
        if path.is_symlink():
            target = path.resolve(strict=False)
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise IntakeError("repository contains a symlink escaping the snapshot") from exc
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        byte_count += size
        if byte_count > _MAX_BYTES:
            raise IntakeError("repository exceeds maximum inspected size")
        relative = path.relative_to(repo_dir).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def acquire_repo(repo_url: str, ref: str | None, workspace: str) -> "ScanMetadata":
    """Acquire a pinned, non-executed public GitHub snapshot as ``ScanMetadata``."""
    ScanMetadata, RunStatus = _schemas()
    normalized = normalize_repo_url(repo_url)
    requested_ref = _safe_ref(ref)
    started = datetime.now(timezone.utc)
    scan_id = str(uuid.uuid4())
    workspace_path = Path(workspace).resolve()
    workspace_path.mkdir(parents=True, exist_ok=True)
    run_dir = workspace_path / scan_id
    repo_dir = run_dir / "repo"
    if run_dir.exists():
        raise IntakeError("generated run directory already exists")
    run_dir.mkdir()

    errors: list[str] = []
    commit_sha: str | None = None
    snapshot_hash: str | None = None
    status = RunStatus.RUNNING
    try:
        clone = _run_git(
            ["clone", "--no-checkout", "--no-recurse-submodules", "--", normalized, str(repo_dir)],
            cwd=run_dir,
        )
        if clone.returncode != 0:
            raise IntakeError("Git clone failed without executing repository content")
        resolved = _run_git(["rev-parse", "--verify", f"{requested_ref}^{{commit}}"], cwd=repo_dir)
        candidate = resolved.stdout.strip()
        if resolved.returncode != 0 or not _FULL_SHA.fullmatch(candidate):
            raise IntakeError("requested ref did not resolve to a commit")
        commit_sha = candidate.lower()
        checkout = _run_git(["checkout", "--detach", "--force", commit_sha], cwd=repo_dir)
        if checkout.returncode != 0:
            raise IntakeError("pinned commit checkout failed")
        snapshot_hash = _inspect_snapshot(repo_dir)
        status = RunStatus.COMPLETE
    except IntakeError as exc:
        errors.append(str(exc))
        status = RunStatus.FAILED

    finished = datetime.now(timezone.utc)
    payload = {
        "schema_version": "1.0",
        "scan_id": scan_id,
        "repo_url": normalized,
        "commit_sha": commit_sha,
        "source_kind": "GIT_PUBLIC",
        "started_at": started.isoformat().replace("+00:00", "Z"),
        "finished_at": finished.isoformat().replace("+00:00", "Z"),
        "status": status,
        "tool_versions": {"git": _git_version()},
        "errors": errors,
        "stage_statuses": {
            "intake": "COMPLETE" if not errors else "FAILED",
            "inventory": "NOT_RUN",
            "graph": "NOT_RUN",
            "advisory": "NOT_RUN",
            "ci": "NOT_RUN",
            "container": "NOT_RUN",
        },
        "database_snapshots": {},
        "source_snapshot_sha256": snapshot_hash,
        "scope_capabilities": {
            "source": "static checkout only; repository code not executed",
            "artifact": "NOT_RUN",
            "ci": "detected during module indexing; not analyzed by intake",
        },
    }
    return ScanMetadata.model_validate(payload)
