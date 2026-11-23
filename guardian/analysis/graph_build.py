"""Canonical graph construction (Role B). Public: ``build_graph``, ``write_graph_db``.

Contract version: project.md §9 / schema_version 1.0 (coded against §9 and the
§28 fixture; validated through ``guardian.schemas.GraphBundle`` when present).
"""

from __future__ import annotations

import json
import re
from collections import deque
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from guardian.adapters import npm as npmmod
from guardian.adapters import syft as syftmod
from guardian.analysis.graph_store import write_graph_db  # noqa: F401  (public re-export)
from guardian.evidence import EvidenceStore, sha256_bytes, stable_id

SCHEMA_VERSION = "1.0"
_LOCKNAMES = ("package-lock.json", "npm-shrinkwrap.json")


def _posix(p: str) -> str:
    return p.replace("\\", "/")


def _as_dict(module: Any) -> dict[str, Any]:
    if isinstance(module, dict):
        d = dict(module)
    elif hasattr(module, "model_dump"):
        d = module.model_dump(mode="json")
    else:
        raise TypeError("module must be a dict or a pydantic ProjectModule")
    # repository-relative paths are POSIX-style in every ID and reference
    for k in ("manifests", "lockfiles", "ci_files", "dockerfiles"):
        d[k] = [_posix(x) for x in d.get(k) or []]
    if isinstance(d.get("relative_path"), str):
        d["relative_path"] = _posix(d["relative_path"])
    return d


def _ptr(key: str) -> str:
    return "/packages/" + key.replace("~", "~0").replace("/", "~1")


def _sanitize_url(url: str | None) -> tuple[str | None, str | None]:
    if not url:
        return None, None
    try:
        s = urlsplit(url)
    except ValueError:
        return None, None
    host = s.hostname
    if not s.scheme or not host:
        return None, None
    port = f":{s.port}" if s.port else ""
    return f"{s.scheme}://{host}{port}{s.path}", host


def _source_type(pkg: npmmod.LockPackage) -> tuple[str, str | None, str | None]:
    resolved = pkg.entry.get("resolved")
    if "node_modules/" not in pkg.key:
        return "WORKSPACE", None, None
    if not isinstance(resolved, str):
        return "UNKNOWN", None, None
    if resolved.startswith(("git+", "git://", "github:")):
        return "GIT", None, None   # never echo git URLs that may embed credentials
    if resolved.startswith("file:"):
        return "LOCAL", None, None
    url, host = _sanitize_url(resolved)
    return ("REGISTRY" if url else "UNKNOWN"), url, host


def _lockfile_for(mod: dict[str, Any]) -> str | None:
    locks = mod.get("lockfiles") or []
    for want in _LOCKNAMES:
        for lf in locks:
            if lf.rsplit("/", 1)[-1] == want:
                return lf
    return None


def _empty_module_result(mod: dict[str, Any], coverage: str, reason: str, graph_stage: str) -> dict[str, Any]:
    mod["coverage"] = coverage
    mod["coverage_reason"] = reason
    stage = dict(mod.get("scan_stage") or {})
    stage["graph"] = graph_stage
    mod["scan_stage"] = stage
    return mod


def _build_npm_module(
    scan_id: str, repo: Path, mod: dict[str, Any], lock_rel: str, store: EvidenceStore,
    comps: list[dict], edges: list[dict], warnings: list[str],
) -> dict[str, Any]:
    mid = mod["module_id"]
    data, raw = npmmod.load_lockfile(repo / lock_rel, repo)
    lock_sha = sha256_bytes(raw)
    try:
        parsed = npmmod.parse_lock(data)
    except npmmod.LockfileError as exc:
        exc.raw = raw
        raise

    ev_cache: dict[str, str] = {}

    _FLAGS = ("dev", "optional", "devOptional", "peer", "inBundle", "hasInstallScript", "os", "cpu", "link")

    def entry_ev(key: str) -> str:
        if key not in ev_cache:
            ent = parsed.packages[key].entry
            observed: dict[str, Any] = {"lockfile_sha256": lock_sha}
            observed.update({f: ent[f] for f in _FLAGS if f in ent})   # only facts actually present
            ev_cache[key] = store.add(
                "LOCKFILE", f"lockfile entry {key or '<root>'} (lockfileVersion {parsed.lockfile_version})",
                source_path=lock_rel, json_pointer=_ptr(key), observed_value=observed,
            )
        return ev_cache[key]

    occ: dict[str, str] = {}
    for key, pkg in parsed.packages.items():
        if key == "" or pkg.is_link:
            continue
        occ[key] = stable_id("occ", scan_id, mid, lock_rel, key)

    def node_id(key: str) -> str:
        return mid if key == "" else occ[key]

    # edges (links resolved to their target occurrence inside parse_lock)
    out_adj: dict[str, list[tuple[str, str]]] = {}
    mod_edges: list[dict] = []
    seen_edge_ids: set[str] = set()
    first_constraint: dict[str, str | None] = {}
    for e in parsed.edges:
        if e.parent not in occ and e.parent != "":
            continue
        if e.child not in occ:
            continue
        src, dst = node_id(e.parent), occ[e.child]
        eid = stable_id("edge", scan_id, src, dst, "DEPENDS_ON", e.scope, lock_rel)
        if eid in seen_edge_ids:
            continue
        seen_edge_ids.add(eid)
        mod_edges.append({
            "edge_id": eid, "source_id": src, "target_id": dst, "relationship": "DEPENDS_ON",
            "evidence_ids": sorted({entry_ev(e.parent), entry_ev(e.child)}),
            "module_id": mid, "resolution": "OBSERVED", "dependency_scope": e.scope,
            "declared_constraint": e.constraint, "source_scope": "SOURCE",
        })
        out_adj.setdefault(src, []).append((dst, e.scope))
        first_constraint.setdefault(dst, e.constraint)

    # directness + scope propagation by BFS from the module root
    depth: dict[str, int] = {mid: 0}
    scopes: dict[str, set[str]] = {mid: set()}
    queue: deque[tuple[str, str | None]] = deque([(mid, None)])
    # (node, inherited scope) states, visited-set bounded by nodes x 4 scopes
    visited_states: set[tuple[str, str]] = set()
    while queue:
        n, inh = queue.popleft()
        for dst, escope in out_adj.get(n, []):
            if n == mid:
                new = escope
            elif inh == "development":
                new = "development"
            elif escope in ("optional", "peer"):
                new = escope
            else:
                new = inh or escope
            if (dst, new) in visited_states:
                continue
            visited_states.add((dst, new))
            scopes.setdefault(dst, set()).add(new)
            if dst not in depth:
                depth[dst] = depth[n] + 1
            queue.append((dst, new))

    n_unreachable = 0
    for key, pkg in parsed.packages.items():
        if key not in occ:
            continue
        oid = occ[key]
        reachable = oid in depth
        if not reachable:
            n_unreachable += 1
        stype, url, host = _source_type(pkg)
        ent = pkg.entry
        sc = set(scopes.get(oid, set()))
        if not sc:
            sc = {"development"} if ent.get("dev") else {"optional"} if ent.get("optional") else {"unknown"}
        directness = "UNRESOLVED" if not reachable else ("DIRECT" if depth[oid] == 1 else "TRANSITIVE")
        ver = pkg.version if stype != "WORKSPACE" or pkg.version else None
        integrity = ent.get("integrity")
        comps.append({
            "package_key": f"npm:{pkg.name}@{ver}" if ver else None,
            "ecosystem": "npm", "name": pkg.name, "resolved_version": ver,
            "declared_constraint": first_constraint.get(oid),
            "purl": (f"pkg:npm/{pkg.name.replace('@', '%40', 1)}@{ver}" if ver else None),
            "occurrence_id": oid, "module_id": mid,
            "source_refs": [f"{lock_rel}#{_ptr(key)}"],
            "resolution": "RESOLVED" if ver else "UNKNOWN_VERSION",
            "evidence_ids": [entry_ev(key)],
            "install_stage_indicator": "HAS_INSTALL_SCRIPT" if ent.get("hasInstallScript") else None,
            "dependency_scopes": sorted(sc), "directness": directness, "license": None,
            "artifact_hashes": [integrity] if isinstance(integrity, str) else [],
            "package_source_type": stype, "resolved_source_url": url, "registry_host": host,
            "source_scope": "SOURCE", "image_presence": "NOT_CHECKED",
            "manifest_refs": [mod["manifests"][0]] if directness == "DIRECT" and mod.get("manifests") else [],
        })
        if not reachable:
            warnings.append(
                f"UNRESOLVED_PARENT: {mod['relative_path']}:{key} present in lockfile but no "
                f"declaring parent found; origin relationship unknown"
            )
    edges.extend(mod_edges)

    n_declared_missing = 0
    for u in parsed.unresolved:
        if u.reason == "OPTIONAL_NOT_INSTALLED":
            continue
        n_declared_missing += 1
        warnings.append(
            f"UNRESOLVED_DECLARATION: {mod['relative_path']}:{u.parent or '<root>'} declares "
            f"{u.name}@{u.constraint} ({u.scope}) but {u.reason}; no edge created"
        )

    partial = n_unreachable > 0 or n_declared_missing > 0
    reason = ""
    if partial:
        reason = (f"{n_unreachable} lockfile package(s) without a known parent; "
                  f"{n_declared_missing} declaration(s) without an installed target")
    mod = _empty_module_result(mod, "PARTIAL" if partial else "RESOLVED", reason, "COMPLETE" if not partial else "PARTIAL")
    mod["scan_stage"]["inventory"] = "COMPLETE"
    mod["scanner_names"] = sorted(set(mod.get("scanner_names") or []) | {"guardian-npm-lock-parser"})
    mod["file_counts"] = {**(mod.get("file_counts") or {}), "lockfiles_found": len(mod.get("lockfiles") or []),
                          "lockfiles_scanned": 1, "lock_packages": len(occ)}
    return mod


def _build_declared_only(
    scan_id: str, repo: Path, mod: dict[str, Any], store: EvidenceStore,
    comps: list[dict], edges: list[dict], reason: str,
) -> dict[str, Any]:
    """No usable lockfile: declarations only, no resolved versions, no OBSERVED edges."""
    mid = mod["module_id"]
    manifest = next((m for m in mod.get("manifests", []) if m.rsplit("/", 1)[-1] == "package.json"), None)
    if manifest:
        try:
            pj = json.loads((repo / manifest).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pj = {}
        for fname, scope in (("dependencies", "production"), ("devDependencies", "development"),
                             ("optionalDependencies", "optional"), ("peerDependencies", "peer")):
            deps = pj.get(fname) if isinstance(pj, dict) else None
            for name, constraint in (deps or {}).items() if isinstance(deps, dict) else []:
                ev = store.add("MANIFEST", f"manifest declares {name}@{constraint} ({scope})",
                               source_path=manifest, json_pointer=f"/{fname}/{name}")
                oid = stable_id("occ", scan_id, mid, manifest, f"declared:{fname}:{name}")
                comps.append({
                    "package_key": None, "ecosystem": "npm", "name": name, "resolved_version": None,
                    "declared_constraint": str(constraint), "purl": None, "occurrence_id": oid,
                    "module_id": mid, "source_refs": [f"{manifest}#/{fname}/{name}"],
                    "resolution": "DECLARED_ONLY", "evidence_ids": [ev], "install_stage_indicator": None,
                    "dependency_scopes": [scope], "directness": "DIRECT", "license": None,
                    "artifact_hashes": [], "package_source_type": "UNKNOWN", "resolved_source_url": None,
                    "registry_host": None, "source_scope": "SOURCE", "image_presence": "NOT_CHECKED",
                    "manifest_refs": [manifest],
                })
                edges.append({
                    "edge_id": stable_id("edge", scan_id, mid, oid, "DECLARES", scope),
                    "source_id": mid, "target_id": oid, "relationship": "DECLARES",
                    "evidence_ids": [ev], "module_id": mid, "resolution": "UNRESOLVED",
                    "dependency_scope": scope, "declared_constraint": str(constraint),
                    "source_scope": "SOURCE",
                })
    mod = _empty_module_result(mod, "DECLARED_ONLY", reason, "PARTIAL")
    mod["scan_stage"]["inventory"] = "PARTIAL"
    return mod


def _syft_crosscheck(syft: dict[str, Any], comps: list[dict], warnings: list[str]) -> None:
    if syft.get("status") != "COMPLETE":
        warnings.append(f"SYFT_{syft.get('status')}: {syft.get('reason', '')}".rstrip(": "))
        return
    if syft.get("cdx_warning"):
        warnings.append(f"SYFT_CDX_INVALID: {syft['cdx_warning']}")
    syft_set = {(p["name"], p["version"]) for p in syft["packages"] if p.get("type") in ("npm", None)}
    lock_set = {(c["name"], c["resolved_version"]) for c in comps if c["resolved_version"]}
    only_syft, only_lock = syft_set - lock_set, lock_set - syft_set
    warnings.append(
        f"SYFT_RELATIONSHIPS: {syft['relationship_kind']}; syft packages={len(syft_set)} "
        f"lockfile packages={len(lock_set)}"
    )
    if only_syft or only_lock:
        warnings.append(
            f"SCANNER_CONFLICT: {len(only_syft)} package(s) only in Syft, {len(only_lock)} only in lockfile; "
            f"both observations retained (graph edges come from the lockfile)"
        )


def build_graph_with_evidence(
    scan_id: str, repo_dir: str, modules: list[Any], run_dir: str | None = None,
    use_syft: bool = True,
) -> tuple[Any, EvidenceStore]:
    repo = Path(repo_dir)
    store = EvidenceStore(scan_id, run_dir)
    comps: list[dict] = []
    edges: list[dict] = []
    warnings: list[str] = []
    out_modules: list[dict] = []

    for m in modules:
        mod = _as_dict(m)
        before = (len(comps), len(edges), len(warnings))
        try:
            if mod.get("ecosystem") != "npm":
                mod = _empty_module_result(
                    mod, mod.get("coverage") if mod.get("coverage") in ("UNSUPPORTED", "FAILED", "DECLARED_ONLY", "NOT_RUN") else "UNSUPPORTED",
                    mod.get("coverage_reason") or f"no dependency-graph parser for ecosystem {mod.get('ecosystem')!r}", "NOT_RUN")
                warnings.append(f"UNSUPPORTED_MODULE: {mod['relative_path']} ({mod.get('ecosystem')}) has no graph; not treated as clean")
            else:
                lock_rel = _lockfile_for(mod)
                if lock_rel is None:
                    mod = _build_declared_only(scan_id, repo, mod, store, comps, edges,
                                               "no package-lock.json/npm-shrinkwrap.json; versions and edges unknown")
                else:
                    mod = _build_npm_module(scan_id, repo, mod, lock_rel, store, comps, edges, warnings)
        except (npmmod.LockfileError, OSError, KeyError, TypeError, ValueError) as exc:
            del comps[before[0]:], edges[before[1]:], warnings[before[2]:]  # drop partial output of this module only
            raw = getattr(exc, "raw", None)
            if raw is not None:                                   # keep the offending bytes, hashed
                rel, sha = store.save_raw(f"lockfile-failed-{sha256_bytes(raw)[:12]}.json", raw[:5_000_000])
                store.add("LOCKFILE", f"lockfile could not be parsed: {exc}", source_path=_lockfile_for(mod),
                          raw_artifact=rel, raw_sha256=sha)
            mod = _empty_module_result(mod, "FAILED", f"graph build failed: {exc}", "FAILED")
            warnings.append(f"MODULE_FAILED: {mod.get('relative_path')}: {exc}")
        out_modules.append(mod)

    if use_syft:
        _syft_crosscheck(syftmod.run_syft(repo, store), comps, warnings)

    cov = [m["coverage"] for m in out_modules]
    summary = {
        "total_modules": len(out_modules),
        "resolved_modules": cov.count("RESOLVED"),
        "partial_modules": cov.count("PARTIAL"),
        "declared_only_modules": cov.count("DECLARED_ONLY"),
        "unsupported_modules": cov.count("UNSUPPORTED"),
        "failed_modules": cov.count("FAILED"),
    }
    bundle: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "modules": out_modules,
        "components": comps, "edges": edges, "coverage_summary": summary, "warnings": warnings,
    }
    store.flush()
    try:
        from guardian.schemas import GraphBundle  # C's canonical model, when merged
    except ImportError:
        return bundle, store
    return GraphBundle.model_validate(bundle), store


def build_graph(scan_id: str, repo_dir: str, modules: list[Any], run_dir: str | None = None,
                use_syft: bool = True) -> Any:
    """§9.4 signature (``run_dir``/``use_syft`` are optional additions).

    Returns ``guardian.schemas.GraphBundle`` when C's schema is importable,
    otherwise the identical plain dict.
    """
    return build_graph_with_evidence(scan_id, repo_dir, modules, run_dir, use_syft)[0]


def graph_to_dict(graph: Any) -> dict[str, Any]:
    return graph if isinstance(graph, dict) else graph.model_dump(mode="json")


def build_and_write(scan_id: str, repo_dir: str, modules: list[Any], run_dir: str) -> dict[str, str]:
    """Convenience: write evidence.jsonl, graph.json and graph.sqlite into ``run_dir``."""
    graph, _ = build_graph_with_evidence(scan_id, repo_dir, modules, run_dir)
    d = graph_to_dict(graph)
    out = Path(run_dir)
    (out / "graph.json").write_text(json.dumps(d, indent=2, sort_keys=True), encoding="utf-8")
    write_graph_db(graph, str(out / "graph.sqlite"))
    return {"graph": str(out / "graph.json"), "db": str(out / "graph.sqlite"),
            "evidence": str(out / "evidence.jsonl")}
