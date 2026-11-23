"""Independent graph oracle (Role E, PROJECT.md sections 15.E1, 17, 21.1).

Compares a GraphBundle produced by the production pipeline (B's ``graph.json``)
against the hand-written expectations in ``ground_truth.yaml``.  The oracle
never derives expectations from production output.

Occurrence matching
    B's occurrence ids are hashes, so the oracle maps each component back to
    ``(module relative_path, lockfile location)``.  The location is read from a
    ``source_refs`` entry that contains a JSON pointer into the lockfile
    ``packages`` map, for example ``package-lock.json#/packages/node_modules~1fx-alpha``
    (RFC 6901 escaping: ``~1`` = ``/``, ``~0`` = ``~``).  When no such reference
    exists the oracle falls back to a unique ``(module, name, version)`` match and
    records a warning.

Usage
    python -m eval.graph_oracle --graph runs/<id>/graph.json --fixture m1-oracle
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = "ROOT"
_DEPENDENCY_RELATIONSHIPS = {"DECLARES", "DEPENDS_ON"}
DEFAULT_GROUND_TRUTH = Path(__file__).resolve().parents[1] / "ground_truth.yaml"


# ----------------------------------------------------------------------------- loading
def load_ground_truth(path: str | Path = DEFAULT_GROUND_TRUTH) -> dict[str, Any]:
    import yaml  # PyYAML; safe loader only

    with open(path, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict) or data.get("schema") != "e-ground-truth/1":
        raise ValueError("ground truth file has an unexpected schema marker")
    return data


def find_fixture(ground_truth: dict[str, Any], fixture_id: str) -> dict[str, Any]:
    for section in ("graph_fixtures", "cross_role_fixtures"):
        for entry in ground_truth.get(section) or []:
            if entry.get("id") == fixture_id:
                return entry
    raise KeyError(f"fixture {fixture_id!r} not found in ground truth")


def normalized_sha256(path: Path) -> str:
    """sha256 of the file after CRLF -> LF normalisation (stable across git checkouts)."""
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def verify_fixture_files(entry: dict[str, Any], repo_root: str | Path) -> list[str]:
    """Return a list of problems; empty when every pinned fixture file matches."""
    base = Path(repo_root) / entry["path"]
    problems = []
    for relative, expected in sorted((entry.get("files") or {}).items()):
        target = base / relative
        if not target.is_file():
            problems.append(f"missing fixture file {entry['path']}/{relative}")
            continue
        actual = normalized_sha256(target)
        if actual != expected:
            problems.append(f"fixture file changed {entry['path']}/{relative}: {actual} != {expected}")
    return problems


# ----------------------------------------------------------------------------- mapping
def _as_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


def location_from_refs(refs: list[str] | None) -> str | None:
    for ref in refs or []:
        if "#/packages/" not in ref:
            continue
        pointer = ref.split("#/packages/", 1)[1]
        return pointer.replace("~1", "/").replace("~0", "~")
    return None


class _Mapped:
    def __init__(self, graph: dict[str, Any]):
        self.graph = graph
        self.module_path = {m["module_id"]: m.get("relative_path") for m in graph.get("modules") or []}
        self.module_id = {path: mid for mid, path in self.module_path.items()}
        self.occ: dict[str, tuple[str, str | None]] = {}
        self.warnings: list[str] = []
        by_identity: dict[tuple, list[dict]] = defaultdict(list)
        for comp in graph.get("components") or []:
            by_identity[(comp.get("module_id"), comp.get("name"), comp.get("resolved_version"))].append(comp)
        for comp in graph.get("components") or []:
            module = self.module_path.get(comp.get("module_id"))
            location = location_from_refs(comp.get("source_refs"))
            if location is None and comp.get("resolved_version") is not None:
                same = by_identity[(comp.get("module_id"), comp.get("name"), comp.get("resolved_version"))]
                if len(same) == 1:
                    location = f"?{comp.get('name')}@{comp.get('resolved_version')}"
                    self.warnings.append(
                        f"component {comp.get('name')}@{comp.get('resolved_version')} has no lockfile "
                        "pointer in source_refs; matched by unique name+version"
                    )
            self.occ[comp["occurrence_id"]] = (module, location)
        self.components = graph.get("components") or []

    def apply_expectations(self, entry: dict[str, Any]) -> None:
        """Translate name+version fallbacks into the single expected lockfile location."""
        for oid, (module, location) in list(self.occ.items()):
            if not location or not location.startswith("?"):
                continue
            name, _, version = location[1:].rpartition("@")
            candidates = [c.get("location") for c in entry.get("components") or []
                          if c["module"] == module and c["name"] == name and c.get("version") == version]
            if len(candidates) == 1 and candidates[0]:
                self.occ[oid] = (module, candidates[0])

    def node_key(self, node_id: str) -> tuple[str | None, str | None]:
        if node_id in self.module_path:
            return self.module_path[node_id], ROOT
        return self.occ.get(node_id, (None, None))


def _find_component(mapped: _Mapped, expected: dict[str, Any]) -> dict[str, Any] | None:
    module, location = expected["module"], expected.get("location")
    for comp in mapped.components:
        cmod, cloc = mapped.occ.get(comp["occurrence_id"], (None, None))
        if cmod != module:
            continue
        if location is not None:
            if cloc == location:
                return comp
            if cloc == f"?{expected['name']}@{expected.get('version')}":
                return comp
        elif comp.get("name") == expected["name"]:
            return comp
    return None


# ----------------------------------------------------------------------------- comparison
def compare_graph(graph: Any, entry: dict[str, Any]) -> dict[str, Any]:
    """Compare one GraphBundle (dict or pydantic model) with one ground-truth entry."""
    graph = _as_dict(graph)
    mapped = _Mapped(graph)
    mapped.apply_expectations(entry)
    errors: list[str] = []
    warnings: list[str] = list(mapped.warnings)

    # modules and coverage
    expected_modules = {m["path"]: m for m in entry.get("modules") or []}
    graph_modules = {m.get("relative_path"): m for m in graph.get("modules") or []}
    for path, exp in expected_modules.items():
        got = graph_modules.get(path)
        if got is None:
            errors.append(f"module {path!r} missing from graph")
            continue
        if exp.get("ecosystem") and got.get("ecosystem") != exp["ecosystem"]:
            errors.append(f"module {path!r} ecosystem {got.get('ecosystem')!r} != {exp['ecosystem']!r}")
        if got.get("coverage") not in exp["coverage"]:
            errors.append(f"module {path!r} coverage {got.get('coverage')!r} not in {exp['coverage']}")
        if got.get("coverage") != "RESOLVED" and not (got.get("coverage_reason") or "").strip():
            errors.append(f"module {path!r} is {got.get('coverage')} without a coverage_reason")
    resolved_modules = {p for p, m in expected_modules.items() if m["coverage"] == ["RESOLVED"]}

    # components
    matched_ids = set()
    for exp in entry.get("components") or []:
        comp = _find_component(mapped, exp)
        label = f"{exp['module']}:{exp.get('location') or exp['name']}"
        if comp is None:
            errors.append(f"component {label} missing")
            continue
        matched_ids.add(comp["occurrence_id"])
        if comp.get("name") != exp["name"]:
            errors.append(f"component {label} name {comp.get('name')!r} != {exp['name']!r}")
        if comp.get("resolved_version") != exp.get("version"):
            errors.append(f"component {label} resolved_version {comp.get('resolved_version')!r} != {exp.get('version')!r}")
        if exp.get("directness") and comp.get("directness") != exp["directness"]:
            errors.append(f"component {label} directness {comp.get('directness')!r} != {exp['directness']!r}")
        if exp.get("constraint") is not None and comp.get("declared_constraint") != exp["constraint"]:
            errors.append(f"component {label} declared_constraint {comp.get('declared_constraint')!r} != {exp['constraint']!r}")
        if exp.get("resolution") and comp.get("resolution") not in exp["resolution"]:
            errors.append(f"component {label} resolution {comp.get('resolution')!r} not in {exp['resolution']}")
        scopes = set(comp.get("dependency_scopes") or [])
        for scope in exp.get("scopes_include") or []:
            if scope not in scopes:
                errors.append(f"component {label} lacks scope {scope!r} (has {sorted(scopes)})")
        for scope in exp.get("scopes_exclude") or []:
            if scope in scopes:
                errors.append(f"component {label} wrongly has scope {scope!r}")
    for comp in mapped.components:
        module, _ = mapped.occ.get(comp["occurrence_id"], (None, None))
        if module in resolved_modules and comp["occurrence_id"] not in matched_ids and comp.get("resolved_version"):
            errors.append(f"unexpected resolved component {comp.get('name')}@{comp.get('resolved_version')} in {module!r}")

    # observed dependency edges per supported module
    observed: dict[str, dict[tuple[str, str], set[str]]] = defaultdict(lambda: defaultdict(set))
    observed_constraints: dict[tuple[str, str, str], str | None] = {}
    for edge in graph.get("edges") or []:
        if edge.get("resolution") != "OBSERVED" or edge.get("relationship") not in _DEPENDENCY_RELATIONSHIPS:
            continue
        smod, sloc = mapped.node_key(edge.get("source_id"))
        tmod, tloc = mapped.node_key(edge.get("target_id"))
        if smod is None or tmod is None or sloc is None or tloc is None:
            errors.append(f"OBSERVED edge {edge.get('edge_id')} has an endpoint that cannot be mapped")
            continue
        if smod != tmod:
            errors.append(f"OBSERVED edge {edge.get('edge_id')} crosses modules {smod!r} -> {tmod!r}")
            continue
        observed[smod][(sloc, tloc)].add(edge.get("relationship"))
        observed_constraints[(smod, sloc, tloc)] = edge.get("declared_constraint")
    expected_edges: dict[str, dict[tuple[str, str], dict]] = defaultdict(dict)
    for exp in entry.get("edges") or []:
        expected_edges[exp["module"]][(exp["from"], exp["to"])] = exp
    for module in sorted(set(expected_edges) | (set(observed) & resolved_modules)):
        exp_pairs = expected_edges.get(module, {})
        got_pairs = observed.get(module, {})
        for pair, exp in sorted(exp_pairs.items()):
            if pair not in got_pairs:
                errors.append(f"edge missing in {module!r}: {pair[0]} -> {pair[1]}")
                continue
            bad = got_pairs[pair] - set(exp["relationship"])
            if bad:
                errors.append(f"edge {pair[0]} -> {pair[1]} in {module!r} has relationship {sorted(bad)}")
            constraint = observed_constraints.get((module, *pair))
            if exp.get("constraint") is not None:
                if constraint is None:
                    warnings.append(f"edge {pair[0]} -> {pair[1]} in {module!r} records no declared_constraint")
                elif constraint != exp["constraint"]:
                    errors.append(f"edge {pair[0]} -> {pair[1]} constraint {constraint!r} != {exp['constraint']!r}")
        if module in resolved_modules:
            for pair in sorted(set(got_pairs) - set(exp_pairs)):
                errors.append(f"invented edge in {module!r}: {pair[0]} -> {pair[1]}")

    # unresolved declarations: never invented, always reported
    all_text = json.dumps({"edges": graph.get("edges"), "warnings": graph.get("warnings"),
                           "components": graph.get("components")})
    for decl in entry.get("unresolved_declarations") or []:
        for comp in mapped.components:
            if comp.get("name") == decl["name"] and comp.get("resolution") == "RESOLVED":
                errors.append(f"unresolved declaration {decl['name']!r} was turned into a RESOLVED component")
        if decl["name"] not in all_text:
            errors.append(f"unresolved declaration {decl['name']!r} from {decl['from']} is not reported anywhere")

    # paths, recomputed from the observed edges only
    for exp in entry.get("paths") or []:
        module = exp["module"]
        adjacency: dict[str, set[str]] = defaultdict(set)
        for (src, dst) in observed.get(module, {}):
            adjacency[src].add(dst)
        dist = {ROOT: 0}
        queue = deque([ROOT])
        while queue:
            node = queue.popleft()
            for nxt in sorted(adjacency[node]):
                if nxt not in dist:
                    dist[nxt] = dist[node] + 1
                    queue.append(nxt)
        target = exp["target"]
        if "FOUND" in exp["status"]:
            via = exp["via"]
            if target not in dist:
                errors.append(f"no path to {target} in {module!r}, expected {' -> '.join(via)}")
                continue
            if dist[target] != len(via) - 1:
                errors.append(f"shortest path to {target} has length {dist[target]}, expected {len(via) - 1}")
            for src, dst in zip(via, via[1:]):
                if dst not in adjacency[src]:
                    errors.append(f"expected path step {src} -> {dst} missing in {module!r}")
        elif target in dist:
            errors.append(f"path to {target} found in {module!r}, expected one of {exp['status']}")

    # identity bookkeeping
    ident = entry.get("identities") or {}
    resolved = [c for c in mapped.components if c.get("resolved_version") is not None and c.get("resolution") == "RESOLVED"]
    identities = {(c.get("ecosystem"), c.get("name"), c.get("resolved_version")) for c in resolved}
    if "resolved_identity_count" in ident and len(identities) != ident["resolved_identity_count"]:
        errors.append(f"resolved identity count {len(identities)} != {ident['resolved_identity_count']}")
    if "resolved_occurrence_count" in ident and len(resolved) != ident["resolved_occurrence_count"]:
        errors.append(f"resolved occurrence count {len(resolved)} != {ident['resolved_occurrence_count']}")
    for shared in ident.get("shared_across_modules") or []:
        count = sum(1 for c in resolved if c.get("name") == shared["name"] and c.get("resolved_version") == shared["version"])
        if count != shared["occurrences"]:
            errors.append(f"{shared['name']}@{shared['version']} has {count} occurrences, expected {shared['occurrences']}")
        keys = {c.get("package_key") for c in resolved
                if c.get("name") == shared["name"] and c.get("resolved_version") == shared["version"]}
        if len(keys) > 1:
            errors.append(f"{shared['name']}@{shared['version']} has {len(keys)} different package_keys, expected one identity")

    # must-not rules
    for rule in entry.get("must_not") or []:
        kind = rule["rule"]
        if kind == "no_resolved_component_named":
            if any(c.get("name") == rule["name"] and c.get("resolved_version") for c in mapped.components):
                errors.append(f"must_not: a resolved component named {rule['name']!r} exists")
        elif kind == "no_incoming_edge":
            if any(dst == rule["target"] for (_, dst) in observed.get(rule["module"], {})):
                errors.append(f"must_not: an observed edge points to {rule['target']} in {rule['module']!r}")
        elif kind == "no_resolved_version_in_module":
            for comp in mapped.components:
                module, _ = mapped.occ.get(comp["occurrence_id"], (None, None))
                if module == rule["module"] and comp.get("resolved_version") is not None:
                    errors.append(f"must_not: {comp.get('name')} in {rule['module']!r} has resolved_version {comp.get('resolved_version')!r}")
        else:
            warnings.append(f"unknown must_not rule {kind!r}")

    return {"fixture": entry.get("id"), "ok": not errors, "errors": errors, "warnings": warnings}


# ----------------------------------------------------------------------------- reference bundle
def reference_bundle(entry: dict[str, Any], scan_id: str = "e-oracle-reference") -> dict[str, Any]:
    """A GraphBundle-shaped dict that satisfies ``entry`` exactly.

    For the oracle's own self-tests and for consumers (C/D) that need a valid
    example before B's builder is merged.  It is labelled as a fixture.
    """
    modules, components, edges, evidence_ids = [], [], [], []
    mid = {}
    for i, mod in enumerate(entry.get("modules") or []):
        module_id = f"mod:fixture-{i}"
        mid[mod["path"]] = module_id
        coverage = mod["coverage"][0]
        modules.append({
            "module_id": module_id, "relative_path": mod["path"], "ecosystem": mod.get("ecosystem", "npm"),
            "manifests": [], "lockfiles": [], "ci_files": [], "dockerfiles": [],
            "coverage": coverage, "coverage_reason": "" if coverage == "RESOLVED" else "reference fixture",
            "scanner_names": ["e-reference-bundle"], "file_counts": {}, "scan_stage": {},
            "artifact_sbom_status": "NOT_RUN",
        })
    occ_id = {}
    for i, comp in enumerate(entry.get("components") or []):
        oid = f"occ:fixture-{i}"
        key = (comp["module"], comp.get("location") or comp["name"])
        occ_id[key] = oid
        lockfile = "package-lock.json" if comp["module"] == "." else f"{comp['module']}/package-lock.json"
        refs = [f"{lockfile}#/packages/{comp['location'].replace('~', '~0').replace('/', '~1')}"] if comp.get("location") else []
        version = comp.get("version")
        scopes = list(comp.get("scopes_include") or (["unknown"] if version is None else ["production"]))
        components.append({
            "package_key": f"npm:{comp['name']}@{version}" if version else None,
            "ecosystem": "npm", "name": comp["name"], "resolved_version": version,
            "declared_constraint": comp.get("constraint"), "purl": f"pkg:npm/{comp['name']}@{version}" if version else None,
            "occurrence_id": oid, "module_id": mid[comp["module"]], "source_refs": refs,
            "resolution": (comp.get("resolution") or ["RESOLVED"])[0], "evidence_ids": ["ev:fixture-lockfile"],
            "install_stage_indicator": None, "dependency_scopes": scopes,
            "directness": comp.get("directness", "TRANSITIVE"), "license": None, "artifact_hashes": [],
            "package_source_type": "UNKNOWN", "resolved_source_url": None, "registry_host": None,
            "source_scope": "SOURCE", "image_presence": "NOT_CHECKED", "manifest_refs": [],
        })
    for i, edge in enumerate(entry.get("edges") or []):
        source = mid[edge["module"]] if edge["from"] == ROOT else occ_id[(edge["module"], edge["from"])]
        edges.append({
            "edge_id": f"edge:fixture-{i}", "source_id": source, "target_id": occ_id[(edge["module"], edge["to"])],
            "relationship": edge["relationship"][-1], "evidence_ids": ["ev:fixture-lockfile"],
            "module_id": mid[edge["module"]], "resolution": "OBSERVED", "dependency_scope": "production",
            "declared_constraint": edge.get("constraint"), "source_scope": "SOURCE",
        })
    warnings = [f"unresolved declaration {d['name']} ({d['constraint']}) from {d['from']} in {d['module']}"
                for d in entry.get("unresolved_declarations") or []]
    for i, comp in enumerate(components):
        if comp["directness"] == "UNRESOLVED":
            warnings.append(f"no known parent for {comp['name']}@{comp['resolved_version']}")
    summary = {"total_modules": len(modules)}
    for cov in ("RESOLVED", "PARTIAL", "DECLARED_ONLY", "UNSUPPORTED", "FAILED"):
        summary[f"{cov.lower()}_modules"] = sum(1 for m in modules if m["coverage"] == cov)
    return {"schema_version": "1.0", "scan_id": scan_id, "modules": modules, "components": components,
            "edges": edges, "coverage_summary": summary, "warnings": warnings}


# ----------------------------------------------------------------------------- CLI
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare a graph.json against Role E's ground truth")
    parser.add_argument("--graph", required=True, help="path to a GraphBundle JSON file")
    parser.add_argument("--fixture", required=True, help="ground-truth fixture id, e.g. m1-oracle")
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH))
    args = parser.parse_args(argv)
    truth = load_ground_truth(args.ground_truth)
    entry = find_fixture(truth, args.fixture)
    with open(args.graph, encoding="utf-8") as handle:
        graph = json.load(handle)
    report = compare_graph(graph, entry)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
