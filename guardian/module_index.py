"""Static project-root discovery for an already authorized snapshot."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from guardian.schemas import ProjectModule


_IGNORED_DIRS = {
    ".git", ".hg", ".svn", ".venv", "venv", "node_modules", "dist", "build",
    "target", "vendor", "__pycache__", ".pytest_cache", ".mypy_cache",
}

_MANIFESTS = {
    "package.json": "npm", "pyproject.toml": "pypi", "Pipfile": "pypi",
    "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
    "go.mod": "go", "Cargo.toml": "cargo",
}
_LOCKFILES = {
    "package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "poetry.lock": "pypi",
    "uv.lock": "pypi", "Pipfile.lock": "pypi", "gradle.lockfile": "gradle",
    "go.sum": "go", "Cargo.lock": "cargo",
}
_DEEP_GRAPH_SUPPORTED = {"npm"}


class ModuleIndexError(RuntimeError):
    """Static module indexing could not safely continue."""


def _project_module() -> type[Any]:
    try:
        from guardian.schemas import ProjectModule
    except (ImportError, ModuleNotFoundError) as exc:
        raise ModuleIndexError(
            "guardian.schemas is unavailable; C's canonical contract must be merged"
        ) from exc
    return ProjectModule


def _relative(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix() or "."


def _module_id(scan_id: str, relative_path: str, ecosystem: str) -> str:
    value = f"{scan_id}\x00{relative_path}\x00{ecosystem}".encode("utf-8")
    return f"mod:{hashlib.sha256(value).hexdigest()[:24]}"


def _safe_files(repo_dir: Path) -> list[Path]:
    root = repo_dir.resolve(strict=True)
    files: list[Path] = []
    for path in repo_dir.rglob("*"):
        relative = path.relative_to(repo_dir)
        if any(part in _IGNORED_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            try:
                path.resolve(strict=False).relative_to(root)
            except ValueError as exc:
                raise ModuleIndexError(f"symlink escapes repository: {relative.as_posix()}") from exc
            continue
        if path.is_file():
            files.append(path)
    return files


def index_modules(scan_id: str, repo_dir: str) -> list["ProjectModule"]:
    """Detect module roots without parsing or executing repository dependencies."""
    ProjectModule = _project_module()
    root = Path(repo_dir)
    if not scan_id:
        raise ModuleIndexError("scan_id is required")
    if not root.is_dir():
        raise ModuleIndexError("repository directory does not exist")
    files = _safe_files(root)

    grouped: dict[tuple[Path, str], dict[str, list[str]]] = {}
    ci_files = [
        _relative(root, p) for p in files
        if len(p.relative_to(root).parts) >= 3
        and p.relative_to(root).parts[:2] == (".github", "workflows")
        and p.suffix.lower() in {".yml", ".yaml"}
    ]
    dockerfiles = [
        _relative(root, p) for p in files
        if p.name.startswith("Dockerfile")
        or p.name.lower().startswith("compose.")
        or p.name.lower() in {"docker-compose.yml", "docker-compose.yaml"}
    ]
    for path in files:
        ecosystem = _MANIFESTS.get(path.name)
        kind = "manifests"
        if ecosystem is None:
            ecosystem = _LOCKFILES.get(path.name)
            kind = "lockfiles"
        if ecosystem is None and path.name.startswith("requirements") and path.suffix == ".txt":
            ecosystem, kind = "pypi", "manifests"
        if ecosystem is None:
            continue
        record = grouped.setdefault((path.parent, ecosystem), {"manifests": [], "lockfiles": []})
        record[kind].append(_relative(root, path))

    modules = []
    for (module_root, ecosystem), discovered in sorted(
        grouped.items(), key=lambda item: (_relative(root, item[0][0]), item[0][1])
    ):
        relative_path = _relative(root, module_root)
        manifests = sorted(discovered["manifests"])
        lockfiles = sorted(discovered["lockfiles"])
        module_ci = [p for p in ci_files if relative_path == "." or p.startswith(relative_path + "/")]
        module_docker = [p for p in dockerfiles if relative_path == "." or p.startswith(relative_path + "/")]
        if ecosystem in _DEEP_GRAPH_SUPPORTED and lockfiles:
            coverage, reason = "PARTIAL", "detected; graph resolution is owned by B and has not run"
        elif lockfiles:
            coverage, reason = "UNSUPPORTED", f"{ecosystem} detected; deep graph parser is not implemented by Role A"
        else:
            coverage, reason = "DECLARED_ONLY", "manifest detected without a supported lockfile"
        payload = {
            "module_id": _module_id(scan_id, relative_path, ecosystem),
            "relative_path": relative_path,
            "ecosystem": ecosystem,
            "manifests": manifests,
            "lockfiles": lockfiles,
            "ci_files": sorted(module_ci),
            "dockerfiles": sorted(module_docker),
            "coverage": coverage,
            "coverage_reason": reason,
            "scanner_names": ["guardian-static-module-index"],
            "file_counts": {
                "manifests_found": len(manifests), "manifests_scanned": len(manifests),
                "lockfiles_found": len(lockfiles), "lockfiles_scanned": len(lockfiles),
                "failed": 0, "unsupported": 0 if ecosystem in _DEEP_GRAPH_SUPPORTED else len(lockfiles),
            },
            "scan_stage": {
                "inventory": "COMPLETE", "graph": "NOT_RUN", "advisory": "NOT_RUN",
                "ci": "NOT_RUN", "container": "NOT_RUN",
            },
            "artifact_sbom_status": "NOT_RUN",
        }
        modules.append(ProjectModule.model_validate(payload))
    return modules
