"""Deterministic supply-chain comparison over two canonical Guardian runs.

The comparison uses normalized package identities, occurrence locations, sources,
dependency relations and advisory IDs. It never executes either source checkout.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any


class ComparisonError(ValueError):
    """Raised when a run cannot be compared without inventing missing data."""


def _read(run: Path, name: str) -> dict[str, Any]:
    path = run / name
    if not path.is_file():
        raise ComparisonError(f"{name} is missing from {run}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ComparisonError(f"{name} is unreadable in {run}: {type(exc).__name__}") from exc
    if not isinstance(value, dict):
        raise ComparisonError(f"{name} must contain a JSON object")
    return value


def _modules(graph: dict[str, Any]) -> dict[str, str]:
    return {m["module_id"]: m.get("relative_path", ".") for m in graph.get("modules", [])}


def _location(component: dict[str, Any], modules: dict[str, str]) -> tuple[str, tuple[str, ...]]:
    # source_refs retain the lockfile install path/JSON pointer across scan-specific IDs.
    refs = tuple(sorted(str(ref) for ref in component.get("source_refs", [])))
    return modules.get(component.get("module_id"), component.get("module_id", "unknown")), refs


def _source(component: dict[str, Any]) -> tuple[Any, ...]:
    return (
        component.get("package_source_type", "UNKNOWN"),
        component.get("resolved_source_url"),
        component.get("registry_host"),
        tuple(sorted(component.get("artifact_hashes", []))),
    )


def _component_view(component: dict[str, Any], modules: dict[str, str]) -> dict[str, Any]:
    module, refs = _location(component, modules)
    return {
        "package_key": component.get("package_key"),
        "ecosystem": component.get("ecosystem"),
        "name": component.get("name"),
        "version": component.get("resolved_version"),
        "module": module,
        "source_refs": list(refs),
        "directness": component.get("directness"),
        "source_type": component.get("package_source_type", "UNKNOWN"),
        "source_url": component.get("resolved_source_url"),
        "registry_host": component.get("registry_host"),
    }


def _snapshot(findings: list[dict[str, Any]], metadata: dict[str, Any]) -> list[str]:
    values = {str(f["advisory_as_of"]) for f in findings if f.get("advisory_as_of")}
    values.update(str(v) for v in metadata.get("database_snapshots", {}).values() if v)
    return sorted(values)


def _advisory_key(finding: dict[str, Any], components: dict[str, dict[str, Any]]) -> tuple[Any, ...] | None:
    if finding.get("classification") != "CONFIRMED_ADVISORY":
        return None
    package_keys = sorted({components[o].get("package_key") for o in finding.get("occurrence_ids", []) if o in components})
    advisory_ids = sorted(set(finding.get("advisory_ids", [])) | set(finding.get("advisory_aliases", [])))
    if not package_keys or not advisory_ids:
        return None
    return tuple(package_keys), tuple(advisory_ids)


def _semantic_nodes(graph: dict[str, Any]) -> tuple[dict[str, tuple[Any, ...]], dict[tuple[Any, ...], dict[str, Any]]]:
    modules = _modules(graph)
    node_keys: dict[str, tuple[Any, ...]] = {mid: ("module", path) for mid, path in modules.items()}
    views: dict[tuple[Any, ...], dict[str, Any]] = {}
    for component in graph.get("components", []):
        key = ("occurrence", *_location(component, modules), component.get("package_key"))
        node_keys[component["occurrence_id"]] = key
        views[key] = _component_view(component, modules)
    return node_keys, views


def _edges(graph: dict[str, Any], nodes: dict[str, tuple[Any, ...]]) -> dict[tuple[Any, ...], dict[str, Any]]:
    result = {}
    for edge in graph.get("edges", []):
        source, target = nodes.get(edge.get("source_id")), nodes.get(edge.get("target_id"))
        if source is None or target is None:
            continue
        key = (source, target, edge.get("relationship"), edge.get("dependency_scope"))
        result[key] = {"from": source, "to": target, "relationship": edge.get("relationship"),
                       "scope": edge.get("dependency_scope")}
    return result


def _paths(graph: dict[str, Any], targets: set[tuple[Any, ...]], limit: int) -> list[list[tuple[Any, ...]]]:
    nodes, _ = _semantic_nodes(graph)
    adjacency: dict[tuple[Any, ...], list[tuple[Any, ...]]] = defaultdict(list)
    roots = []
    for key in nodes.values():
        if key[0] == "module":
            roots.append(key)
    for edge in graph.get("edges", []):
        if edge.get("relationship") != "DEPENDS_ON" or edge.get("resolution") not in ("OBSERVED", "INFERRED"):
            continue
        source, target = nodes.get(edge.get("source_id")), nodes.get(edge.get("target_id"))
        if source and target:
            adjacency[source].append(target)
    found: list[list[tuple[Any, ...]]] = []
    for root in sorted(roots, key=str):
        queue = deque([(root, [root])])
        seen = {root}
        while queue and len(found) < limit:
            node, path = queue.popleft()
            if node in targets:
                found.append(path)
                continue
            for child in sorted(adjacency.get(node, []), key=str):
                if child not in seen:
                    seen.add(child)
                    queue.append((child, path + [child]))
    return found


def compare_runs(baseline_run: str | Path, current_run: str | Path, *, max_changes: int = 200) -> dict[str, Any]:
    """Compare two validated run directories and return a bounded JSON-ready delta."""
    if max_changes < 1 or max_changes > 5000:
        raise ComparisonError("max_changes must be between 1 and 5000")
    base, current = Path(baseline_run), Path(current_run)
    bm, cm = _read(base, "metadata.json"), _read(current, "metadata.json")
    bg, cg = _read(base, "graph.json"), _read(current, "graph.json")
    bf = _read(base, "findings.json").get("findings", [])
    cf = _read(current, "findings.json").get("findings", [])
    if bm.get("repo_url") != cm.get("repo_url"):
        raise ComparisonError("runs refer to different repositories")
    bn, bv = _semantic_nodes(bg)
    cn, cv = _semantic_nodes(cg)
    base_keys, current_keys = set(bv), set(cv)
    added_keys, removed_keys = current_keys - base_keys, base_keys - current_keys

    base_by_location = {_location(c, _modules(bg)): c for c in bg.get("components", [])}
    current_by_location = {_location(c, _modules(cg)): c for c in cg.get("components", [])}
    upgrades, source_changes = [], []
    upgraded_before: set[tuple[Any, ...]] = set()
    upgraded_after: set[tuple[Any, ...]] = set()
    for location in sorted(set(base_by_location) & set(current_by_location), key=str):
        before, after = base_by_location[location], current_by_location[location]
        if before.get("package_key") != after.get("package_key") and before.get("name") == after.get("name"):
            upgrades.append({"module": location[0], "source_refs": list(location[1]), "name": after.get("name"),
                             "before_version": before.get("resolved_version"), "after_version": after.get("resolved_version")})
            upgraded_before.add(("occurrence", *location, before.get("package_key")))
            upgraded_after.add(("occurrence", *location, after.get("package_key")))
        if _source(before) != _source(after):
            source_changes.append({"module": location[0], "source_refs": list(location[1]),
                                   "package": after.get("package_key"),
                                   "before": {"type": before.get("package_source_type"), "url": before.get("resolved_source_url"),
                                              "registry": before.get("registry_host"), "hashes": before.get("artifact_hashes", [])},
                                   "after": {"type": after.get("package_source_type"), "url": after.get("resolved_source_url"),
                                             "registry": after.get("registry_host"), "hashes": after.get("artifact_hashes", [])}})

    # An in-place version transition is an upgrade/downgrade, not an add plus remove.
    added_keys -= upgraded_after
    removed_keys -= upgraded_before
    be, ce = _edges(bg, bn), _edges(cg, cn)
    b_components = {c["occurrence_id"]: c for c in bg.get("components", [])}
    c_components = {c["occurrence_id"]: c for c in cg.get("components", [])}
    badv = {_advisory_key(f, b_components): f for f in bf if _advisory_key(f, b_components)}
    cadv = {_advisory_key(f, c_components): f for f in cf if _advisory_key(f, c_components)}
    bsnap, csnap = _snapshot(bf, bm), _snapshot(cf, cm)
    snapshots_equal = bool(bsnap and csnap and bsnap == csnap)
    new_advisories = [cadv[k] for k in sorted(set(cadv) - set(badv), key=str)]
    removed_advisories = [badv[k] for k in sorted(set(badv) - set(cadv), key=str)]
    changed_targets = set(added_keys)
    for finding in new_advisories:
        changed_targets.update(cn[o] for o in finding.get("occurrence_ids", []) if o in cn)
    changed_paths = _paths(cg, changed_targets, min(max_changes, 50))
    total_changes = len(added_keys) + len(removed_keys) + len(upgrades) + len(source_changes) + len(set(ce) ^ set(be))
    return {
        "schema_version": "1.0",
        "repository": bm.get("repo_url"),
        "baseline": {"scan_id": bm.get("scan_id"), "commit_sha": bm.get("commit_sha"),
                     "package_identities": len({c.get("package_key") for c in bg.get("components", []) if c.get("package_key")}),
                     "occurrences": len(bg.get("components", [])), "confirmed_advisories": len(badv)},
        "current": {"scan_id": cm.get("scan_id"), "commit_sha": cm.get("commit_sha"),
                    "package_identities": len({c.get("package_key") for c in cg.get("components", []) if c.get("package_key")}),
                    "occurrences": len(cg.get("components", [])), "confirmed_advisories": len(cadv)},
        "advisory_snapshot": {"baseline": bsnap, "current": csnap,
                              "status": "SAME" if snapshots_equal else "DIFFERENT" if bsnap and csnap else "UNKNOWN",
                              "code_change_attribution_allowed": snapshots_equal},
        "changes": {
            "added_packages": [cv[k] for k in sorted(added_keys, key=str)[:max_changes]],
            "removed_packages": [bv[k] for k in sorted(removed_keys, key=str)[:max_changes]],
            "upgraded_packages": upgrades[:max_changes],
            "changed_sources": source_changes[:max_changes],
            "added_edges": [ce[k] for k in sorted(set(ce) - set(be), key=str)[:max_changes]],
            "removed_edges": [be[k] for k in sorted(set(be) - set(ce), key=str)[:max_changes]],
            "new_advisories": new_advisories[:max_changes],
            "removed_advisories": removed_advisories[:max_changes],
            "changed_paths": changed_paths,
        },
        "total_structural_changes": total_changes,
        "truncated": any(len(items) > max_changes for items in (added_keys, removed_keys, upgrades, source_changes,
                                                                  set(ce) - set(be), set(be) - set(ce))),
        "vulnerability_attribution": (
            "Comparable: both runs used the same advisory snapshot."
            if snapshots_equal else
            "Not attributable to the code change: scan both commits with the same advisory snapshot."
        ),
    }
