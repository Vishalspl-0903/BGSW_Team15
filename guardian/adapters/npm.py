"""npm package-lock v2/v3 parser and edge resolver (Role B, project.md §17).

Edges are derived from each entry's *declared* dependencies resolved with
npm's node_modules lookup (own ``node_modules``, then ancestors) — never from
folder nesting alone. Ambiguity or a missing target yields an unresolved
declaration, never an invented edge. Nothing here executes repository code.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

MAX_LOCK_BYTES = 100 * 1024 * 1024

_DEP_FIELDS = (
    ("dependencies", "production"),
    ("optionalDependencies", "optional"),
    ("peerDependencies", "peer"),
)


class LockfileError(RuntimeError):
    """Lockfile unreadable, malformed or unsupported. ``raw`` keeps the bytes read, if any."""

    def __init__(self, message: str, raw: bytes | None = None) -> None:
        super().__init__(message)
        self.raw = raw


class LockfileOutsideRepo(LockfileError):
    """Lockfile path resolves outside the authorized checkout (never echo the path)."""


@dataclass
class LockPackage:
    key: str                       # installed path, "" for root
    name: str
    version: str | None
    entry: dict[str, Any]
    is_link: bool = False
    link_target: str | None = None


@dataclass
class LockEdge:
    parent: str                    # lock key of the declaring package
    child: str                     # lock key of the resolved target
    declared_name: str
    constraint: str | None
    scope: str                     # production|development|optional|peer


@dataclass
class Unresolved:
    parent: str
    name: str
    constraint: str | None
    scope: str
    reason: str


@dataclass
class ParsedLock:
    lockfile_version: int
    packages: dict[str, LockPackage]
    edges: list[LockEdge] = field(default_factory=list)
    unresolved: list[Unresolved] = field(default_factory=list)
    raw_sha256: str = ""


def name_from_key(key: str) -> str:
    """Package name from an installed path; handles scoped names."""
    if "node_modules/" not in key:
        return key.rsplit("/", 1)[-1] if key else ""
    return key[key.rfind("node_modules/") + len("node_modules/"):]


def _parent_path(key: str) -> str | None:
    """Directory whose node_modules is searched after ``key``'s own."""
    if key == "":
        return None
    idx = key.rfind("node_modules/")
    if idx == -1:
        return ""                  # workspace path: next ancestor is the root
    return key[:idx].rstrip("/")


_EXACT = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def _core(v: str) -> str:
    return v.split("+", 1)[0]


def resolve_candidates(packages: dict[str, LockPackage], requester: str, name: str) -> list[str]:
    """All installed candidates visible from ``requester``, nearest first."""
    out: list[str] = []
    here: str | None = requester
    while here is not None:
        cand = f"{here}/node_modules/{name}" if here else f"node_modules/{name}"
        if cand in packages:
            out.append(cand)
        here = _parent_path(here)
    return out


def resolve_checked(packages: dict[str, LockPackage], requester: str, name: str,
                    constraint: str | None) -> tuple[str | None, str | None]:
    """(target, failure_reason). Never guesses between candidates.

    The nearest candidate is npm's own choice. When the constraint is an exact
    version and that candidate's lockfile version differs, the lockfile is
    inconsistent for this edge: if a farther candidate does match, the choice
    is ambiguous; either way no edge is produced. Range constraints are not
    evaluated (no semver engine), so they are accepted as written.
    """
    cands = resolve_candidates(packages, requester, name)
    if not cands:
        return None, "NO_INSTALLED_TARGET_IN_LOCKFILE"
    near = cands[0]
    if constraint and _EXACT.match(constraint):
        def ok(k: str) -> bool:
            pk = packages[k]
            return pk.is_link or pk.version is None or _core(pk.version) == _core(constraint)
        if not ok(near):
            return None, ("AMBIGUOUS_CANDIDATES" if any(ok(c) for c in cands[1:])
                          else "CANDIDATE_VERSION_MISMATCH")
    return near, None


def resolve_target(packages: dict[str, LockPackage], requester: str, name: str) -> str | None:
    """npm lookup: <requester>/node_modules/<name>, then each ancestor."""
    here: str | None = requester
    while here is not None:
        cand = f"{here}/node_modules/{name}" if here else f"node_modules/{name}"
        if cand in packages:
            return cand
        here = _parent_path(here)
    return None


def load_lockfile(path: str | Path, repo_root: str | Path | None = None) -> tuple[dict[str, Any], bytes]:
    p = Path(path)
    if repo_root is not None:
        try:
            p.resolve(strict=True).relative_to(Path(repo_root).resolve(strict=True))
        except (ValueError, OSError) as exc:
            raise LockfileOutsideRepo("lockfile path outside repository; observation quarantined") from exc
    try:
        if p.stat().st_size > MAX_LOCK_BYTES:
            raise LockfileError(f"lockfile exceeds {MAX_LOCK_BYTES} byte limit")
        raw = p.read_bytes()
    except OSError as exc:
        raise LockfileError(f"cannot read lockfile: {exc.__class__.__name__}") from exc
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise LockfileError(f"malformed lockfile JSON: {exc}", raw) from exc
    if not isinstance(data, dict):
        raise LockfileError("lockfile root is not an object", raw)
    return data, raw


def parse_lock(data: dict[str, Any]) -> ParsedLock:
    version = data.get("lockfileVersion")
    pkgs = data.get("packages")
    if version not in (2, 3):
        raise LockfileError(
            f"lockfileVersion {version!r} unsupported (only v2/v3 'packages' map is parsed)"
        )
    if not isinstance(pkgs, dict) or "" not in pkgs:
        raise LockfileError("lockfile lacks a 'packages' map with a root entry")

    packages: dict[str, LockPackage] = {}
    for key, entry in pkgs.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            raise LockfileError("malformed 'packages' entry")
        link = bool(entry.get("link"))
        packages[key] = LockPackage(
            key=key,
            name=entry.get("name") or name_from_key(key) or str(data.get("name") or ""),
            version=entry.get("version") if isinstance(entry.get("version"), str) else None,
            entry=entry,
            is_link=link,
            link_target=entry.get("resolved") if link else None,
        )

    parsed = ParsedLock(lockfile_version=version, packages=packages)
    for key, pkg in packages.items():
        if pkg.is_link:
            continue  # links are references; the target entry declares
        fields = list(_DEP_FIELDS)
        if key == "" or "node_modules/" not in key:   # root / workspace members
            fields.append(("devDependencies", "development"))
        meta = pkg.entry.get("peerDependenciesMeta") or {}
        for fname, scope in fields:
            deps = pkg.entry.get(fname) or {}
            if not isinstance(deps, dict):
                raise LockfileError(f"{fname} of {key or '<root>'} is not an object")
            for dname, constraint in deps.items():
                target, why = resolve_checked(packages, key, dname, str(constraint))
                if target is not None and packages[target].is_link:
                    target = packages[target].link_target if packages[target].link_target in packages else None
                    if target is None:
                        parsed.unresolved.append(Unresolved(key, dname, str(constraint), scope, "WORKSPACE_LINK_TARGET_MISSING"))
                        continue
                if target is None:
                    optional_absent = why == "NO_INSTALLED_TARGET_IN_LOCKFILE" and (scope == "optional" or (
                        scope == "peer" and isinstance(meta.get(dname), dict) and meta[dname].get("optional")))
                    reason = "OPTIONAL_NOT_INSTALLED" if optional_absent else (why or "NO_INSTALLED_TARGET_IN_LOCKFILE")
                    parsed.unresolved.append(Unresolved(key, dname, str(constraint), scope, reason))
                    continue
                parsed.edges.append(LockEdge(key, target, dname, str(constraint), scope))
    return parsed


# --- offline oracle -------------------------------------------------------

def run_npm_ls_oracle(project_dir: str | Path, timeout: int = 120) -> dict[str, Any]:
    """Run ``npm ls --package-lock-only --all --json`` (offline, read-only).

    Returns argv, npm version, exit code, stdout/stderr text and parsed JSON
    (when parseable). npm may exit nonzero on tree problems; output is kept.
    """
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if npm is None:
        return {"available": False, "reason": "npm not found on PATH"}
    argv = [npm, "ls", "--package-lock-only", "--all", "--json"]
    try:
        ver = subprocess.run([npm, "--version"], capture_output=True, text=True, timeout=30)
        res = subprocess.run(argv, cwd=str(project_dir), capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "reason": f"npm failed to run: {exc.__class__.__name__}"}
    try:
        tree = json.loads(res.stdout) if res.stdout.strip() else None
    except ValueError:
        tree = None
    return {
        "available": True,
        "argv": ["npm", "ls", "--package-lock-only", "--all", "--json"],
        "npm_version": ver.stdout.strip(),
        "exit_code": res.returncode,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "tree": tree,
    }


def oracle_edge_set(tree: dict[str, Any]) -> set[tuple[str, str]]:
    """Flatten an ``npm ls`` tree into {(parent 'name@ver', child 'name@ver')}.

    The root is named ``<root>``. Deduped nodes (``"deduped": true``) still
    carry a version, which is sufficient for identity comparison.
    """
    edges: set[tuple[str, str]] = set()

    def walk(label: str, node: dict[str, Any]) -> None:
        for cname, child in (node.get("dependencies") or {}).items():
            ver = child.get("version")
            if ver is None:
                continue                      # missing/invalid in npm's view
            clabel = f"{cname}@{ver}"
            edges.add((label, clabel))
            if not child.get("deduped"):
                walk(clabel, child)

    walk("<root>", tree)
    return edges
