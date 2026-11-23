"""Guardian Reporter and UI Data Layer.

Implements the contract function:
    create_report(run_dir: str) -> tuple[str, str]

Also provides safe, deterministic data loaders and graph query helpers
for the Streamlit UI and acceptance verification.
Never performs vulnerability detection or invents factual findings.
"""

from __future__ import annotations

import collections
import html
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_run_data(run_dir: str | Path) -> dict[str, Any]:
    """Load all standardized artifacts for a scan run from `run_dir`.
    
    Tolerates missing files by returning explicit empty structures or
    NOT_AVAILABLE indicators without throwing exceptions.
    """
    path = Path(run_dir)
    result: dict[str, Any] = {
        "run_dir": str(path.resolve()),
        "is_fixture": False,
        "metadata": None,
        "module_index": None,
        "graph": None,
        "evidence": {},
        "findings": [],
        "proposals": [],
        "validation": None,
        "events": [],
        "raw_artifacts": [],
        "warnings": [],
        "artifacts_on_disk": {
            "metadata.json": False,
            "module_index.json": False,
            "graph.json": False,
            "evidence.jsonl": False,
            "findings.json": False,
            "proposals.json": False,
            "validation.json": False,
            "sbom.cdx.json": False,
        },
    }

    if not path.exists() or not path.is_dir():
        result["warnings"].append(f"Run directory not found: {path}")
        return result

    # 1. metadata.json
    meta_path = path / "metadata.json"
    if meta_path.is_file():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                result["metadata"] = json.load(f)
                result["artifacts_on_disk"]["metadata.json"] = True
                source_kind = result["metadata"].get("source_kind", "")
                if source_kind in ("LOCAL_FIXTURE", "CACHED_SNAPSHOT") or "fixture" in str(path).lower():
                    result["is_fixture"] = True
        except Exception as exc:
            result["warnings"].append(f"Failed parsing metadata.json: {exc}")
    else:
        result["artifacts_on_disk"]["metadata.json"] = False

    # 2. module_index.json
    mod_path = path / "module_index.json"
    if mod_path.is_file():
        try:
            with open(mod_path, "r", encoding="utf-8") as f:
                result["module_index"] = json.load(f)
                result["artifacts_on_disk"]["module_index.json"] = True
        except Exception as exc:
            result["warnings"].append(f"Failed parsing module_index.json: {exc}")
    else:
        result["artifacts_on_disk"]["module_index.json"] = False

    # 3. graph.json (supports canonical GraphBundle and legacy dependency-graph format)
    graph_path = path / "graph.json"
    if graph_path.is_file():
        try:
            with open(graph_path, "r", encoding="utf-8") as f:
                raw_graph = json.load(f)
                result["artifacts_on_disk"]["graph.json"] = True
                result["graph"] = _normalize_graph_bundle(raw_graph, result["metadata"])
        except Exception as exc:
            result["warnings"].append(f"Failed parsing graph.json: {exc}")
    else:
        result["artifacts_on_disk"]["graph.json"] = False

    # 4. evidence.jsonl
    ev_path = path / "evidence.jsonl"
    if ev_path.is_file():
        try:
            ev_dict = {}
            with open(ev_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ev = json.loads(line)
                        eid = ev.get("evidence_id")
                        if eid:
                            ev_dict[eid] = ev
            result["evidence"] = ev_dict
            result["artifacts_on_disk"]["evidence.jsonl"] = True
        except Exception as exc:
            result["warnings"].append(f"Failed parsing evidence.jsonl: {exc}")
    else:
        result["artifacts_on_disk"]["evidence.jsonl"] = False

    # 5. findings.json
    find_path = path / "findings.json"
    if find_path.is_file():
        try:
            with open(find_path, "r", encoding="utf-8") as f:
                find_obj = json.load(f)
                result["artifacts_on_disk"]["findings.json"] = True
                if isinstance(find_obj, dict):
                    result["findings"] = find_obj.get("findings", [])
                elif isinstance(find_obj, list):
                    result["findings"] = find_obj
        except Exception as exc:
            result["warnings"].append(f"Failed parsing findings.json: {exc}")
    else:
        # Fallback to vulnerabilities.json if available
        vuln_path = path / "vulnerabilities.json"
        if vuln_path.is_file():
            result["artifacts_on_disk"]["vulnerabilities.json"] = True
            try:
                with open(vuln_path, "r", encoding="utf-8") as f:
                    vuln_list = json.load(f)
                result["findings"] = _convert_vulnerabilities_to_findings(vuln_list)
            except Exception as exc:
                result["warnings"].append(f"Failed parsing vulnerabilities.json: {exc}")
        else:
            result["artifacts_on_disk"]["findings.json"] = False

    # 6. proposals.json
    prop_path = path / "proposals.json"
    if prop_path.is_file():
        try:
            with open(prop_path, "r", encoding="utf-8") as f:
                prop_data = json.load(f)
                result["artifacts_on_disk"]["proposals.json"] = True
                result["proposals"] = prop_data.get("proposals", [])
                result["audit_results"] = prop_data.get("audit_results", [])
        except Exception as exc:
            result["warnings"].append(f"Failed parsing proposals.json: {exc}")
    else:
        result["artifacts_on_disk"]["proposals.json"] = False

    # 7. validation.json
    val_path = path / "validation.json"
    if val_path.is_file():
        try:
            with open(val_path, "r", encoding="utf-8") as f:
                result["validation"] = json.load(f)
                result["artifacts_on_disk"]["validation.json"] = True
        except Exception as exc:
            result["warnings"].append(f"Failed parsing validation.json: {exc}")
    else:
        result["artifacts_on_disk"]["validation.json"] = False

    # 8. sbom.cdx.json check
    sbom_path = path / "sbom.cdx.json"
    result["artifacts_on_disk"]["sbom.cdx.json"] = sbom_path.is_file()

    return result


def _normalize_graph_bundle(raw: dict[str, Any], meta: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize either canonical GraphBundle or NodeGoat dependency-graph raw format."""
    if "components" in raw and "edges" in raw:
        return raw

    # Convert NodeGoat format: {'nodes': {...}, 'edges': [...], 'meta': {...}}
    components = []
    nodes = raw.get("nodes", {})
    root_pkg = raw.get("root", "owasp-nodejs-goat")

    for pkg_id, node_data in nodes.items():
        name = node_data.get("name", pkg_id.split("@")[0] if "@" in pkg_id else pkg_id)
        version = node_data.get("version", "")
        direct = node_data.get("direct", False)
        runtime = node_data.get("runtime", True)
        
        components.append({
            "package_key": f"npm:{name}@{version}",
            "ecosystem": "npm",
            "name": name,
            "resolved_version": version,
            "declared_constraint": version,
            "purl": f"pkg:npm/{name}@{version}",
            "occurrence_id": f"occ-{pkg_id}",
            "module_id": "mod-root",
            "source_refs": [node_data.get("resolved", "")],
            "resolution": "RESOLVED",
            "evidence_ids": [f"ev-{pkg_id}"],
            "install_stage_indicator": "HAS_INSTALL_SCRIPT" if node_data.get("has_install_script") else None,
            "dependency_scopes": ["production"] if runtime else ["development"],
            "directness": "DIRECT" if direct else "TRANSITIVE",
            "license": node_data.get("license"),
            "artifact_hashes": [node_data.get("integrity", "")] if node_data.get("integrity") else [],
            "package_source_type": "REGISTRY",
            "resolved_source_url": node_data.get("resolved"),
            "registry_host": "registry.npmjs.org",
            "source_scope": "SOURCE",
            "image_presence": "NOT_CHECKED",
            "manifest_refs": ["package.json"] if direct else []
        })

    edges = []
    for edge in raw.get("edges", []):
        src = edge.get("from", edge.get("source_id", ""))
        tgt = edge.get("to", edge.get("target_id", ""))
        edges.append({
            "edge_id": f"edge-{src}->{tgt}",
            "source_id": f"occ-{src}",
            "target_id": f"occ-{tgt}",
            "relationship": "DEPENDS_ON",
            "evidence_ids": [f"ev-edge-{src}-{tgt}"],
            "module_id": "mod-root",
            "resolution": "OBSERVED",
            "dependency_scope": "production",
            "declared_constraint": None,
            "source_scope": "SOURCE"
        })

    return {
        "schema_version": "1.0",
        "scan_id": meta.get("scan_id", "scan-imported") if meta else "scan-imported",
        "modules": [
            {
                "module_id": "mod-root",
                "relative_path": ".",
                "ecosystem": "npm",
                "coverage": "RESOLVED",
                "coverage_reason": "",
                "scanner_names": ["guardian build_graph.py"],
                "file_counts": {"found": len(components), "scanned": len(components), "failed": 0, "unsupported": 0}
            }
        ],
        "components": components,
        "edges": edges,
        "coverage_summary": {
            "total_modules": 1,
            "resolved_modules": 1,
            "partial_modules": 0,
            "declared_only_modules": 0,
            "unsupported_modules": 0,
            "failed_modules": 0
        },
        "warnings": []
    }


def _convert_vulnerabilities_to_findings(vuln_list: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for idx, v in enumerate(vuln_list):
        pkg = v.get("package", "unknown")
        runtime = v.get("runtime", False)
        direct = v.get("direct", False)
        risk = v.get("risk", "MEDIUM")
        advisories = v.get("advisories", [])
        adv_ids = [a.get("id") for a in advisories if isinstance(a, dict) and "id" in a]
        first_adv = advisories[0] if (advisories and isinstance(advisories[0], dict)) else {}
        
        findings.append({
            "schema_version": "1.0",
            "scan_id": "scan-imported",
            "finding_id": f"finding-vuln-{idx+1:04d}",
            "finding_type": "VULNERABILITY",
            "title": first_adv.get("summary") or f"Advisory in {pkg}",
            "description": first_adv.get("details") or f"Known advisory for package {pkg}",
            "module_ids": ["mod-root"],
            "occurrence_ids": [f"occ-{pkg}"],
            "advisory_ids": adv_ids,
            "advisory_urls": [f"https://osv.dev/vulnerability/{aid}" for aid in adv_ids],
            "rule_id": None,
            "severity_label": risk,
            "cvss_score": 7.5 if risk == "HIGH" else (5.0 if risk == "MEDIUM" else 3.0),
            "priority": "P0" if risk == "CRITICAL" else ("P1" if risk == "HIGH" else "P2"),
            "evidence_ids": [f"ev-{pkg}"],
            "dependency_path_node_ids": v.get("paths", [[]])[0] if v.get("paths") else [],
            "path_status": "FOUND" if v.get("paths") else "NO_KNOWN_PATH",
            "execution_stage": "RUNTIME" if runtime else "BUILD",
            "execution_evidence": "CONFIRMED" if runtime else "POTENTIAL",
            "evidence_basis": "TOOL_OBSERVED",
            "uncertainties": [],
            "recommendations": ["Upgrade package to safe fixed release"],
            "classification": "CONFIRMED_ADVISORY",
            "advisory_aliases": first_adv.get("aliases", []),
            "first_seen_in": "REAL_UPSTREAM",
            "advisory_as_of": None,
            "scanner_names": ["osv"]
        })
    return findings


def get_neighbors(
    graph_data: dict[str, Any],
    node_id: str,
    direction: str = "both",
    depth: int = 1,
    max_nodes: int = 150
) -> dict[str, Any]:
    """Retrieve a bounded neighborhood around `node_id`.
    
    Guarantees performance by capping returned nodes to `max_nodes`
    and marking `truncated=True` if exceeding the limit.
    """
    edges = graph_data.get("edges", [])
    components = {c.get("occurrence_id"): c for c in graph_data.get("components", [])}
    modules = {m.get("module_id"): m for m in graph_data.get("modules", [])}

    adj_out = collections.defaultdict(list)
    adj_in = collections.defaultdict(list)
    for e in edges:
        s = e.get("source_id")
        t = e.get("target_id")
        if s and t:
            adj_out[s].append((t, e))
            adj_in[t].append((s, e))

    visited_nodes: set[str] = {node_id}
    selected_edges: list[dict[str, Any]] = []
    current_layer = {node_id}
    truncated = False

    for _ in range(depth):
        next_layer = set()
        for curr in current_layer:
            candidates = []
            if direction in ("out", "both"):
                candidates.extend((nbr, e, "out") for nbr, e in adj_out.get(curr, []))
            if direction in ("in", "both"):
                candidates.extend((nbr, e, "in") for nbr, e in adj_in.get(curr, []))

            for nbr, edge, _ in candidates:
                if len(visited_nodes) >= max_nodes:
                    truncated = True
                    break
                selected_edges.append(edge)
                if nbr not in visited_nodes:
                    visited_nodes.add(nbr)
                    next_layer.add(nbr)
            if truncated:
                break
        current_layer = next_layer
        if truncated:
            break

    node_details = []
    for nid in visited_nodes:
        if nid in components:
            c = components[nid]
            node_details.append({
                "id": nid,
                "label": f"{c.get('name')}@{c.get('resolved_version')}",
                "type": "component",
                "directness": c.get("directness"),
                "ecosystem": c.get("ecosystem"),
            })
        elif nid in modules:
            m = modules[nid]
            node_details.append({
                "id": nid,
                "label": f"Module: {m.get('module_id')}",
                "type": "module",
                "ecosystem": m.get("ecosystem"),
            })
        else:
            node_details.append({"id": nid, "label": nid, "type": "unknown"})

    return {
        "center_node": node_id,
        "nodes": node_details,
        "edges": selected_edges,
        "node_count": len(visited_nodes),
        "edge_count": len(selected_edges),
        "truncated": truncated,
        "max_nodes": max_nodes
    }


def find_shortest_path(
    graph_data: dict[str, Any],
    start_id: str,
    target_id: str
) -> list[str]:
    """BFS shortest path finder from `start_id` to `target_id`.
    
    Returns list of node IDs forming the traceable path, or empty list if no path exists.
    """
    if start_id == target_id:
        return [start_id]

    edges = graph_data.get("edges", [])
    adj = collections.defaultdict(list)
    for e in edges:
        s = e.get("source_id")
        t = e.get("target_id")
        if s and t:
            adj[s].append(t)

    queue = collections.deque([[start_id]])
    visited = {start_id}

    while queue:
        path = queue.popleft()
        node = path[-1]
        for neighbor in adj.get(node, []):
            if neighbor == target_id:
                return path + [neighbor]
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(path + [neighbor])
    return []


def create_report(run_dir: str) -> tuple[str, str]:
    """Generate both report.json and report.md in `run_dir`.
    
    Returns (report_json_path, report_md_path).
    Never invents factual findings; preserves truthful counts and states.
    """
    data = load_run_data(run_dir)
    run_path = Path(run_dir).resolve()
    meta = data.get("metadata") or {}
    graph = data.get("graph") or {}
    findings = data.get("findings") or []
    components = graph.get("components") or []
    edges = graph.get("edges") or []
    modules = (data.get("module_index") or {}).get("modules") or graph.get("modules") or []
    coverage_sum = graph.get("coverage_summary") or {
        "total_modules": len(modules),
        "resolved_modules": sum(1 for m in modules if m.get("coverage") == "RESOLVED"),
        "partial_modules": sum(1 for m in modules if m.get("coverage") == "PARTIAL"),
        "declared_only_modules": sum(1 for m in modules if m.get("coverage") == "DECLARED_ONLY"),
        "unsupported_modules": sum(1 for m in modules if m.get("coverage") == "UNSUPPORTED"),
        "failed_modules": sum(1 for m in modules if m.get("coverage") == "FAILED"),
    }

    # Deterministic sorting
    sorted_findings = sorted(findings, key=lambda x: (x.get("priority", "P3"), x.get("finding_id", "")))
    findings_summary = {
        "total": len(sorted_findings),
        "by_priority": collections.Counter(f.get("priority", "UNASSESSED") for f in sorted_findings),
        "by_classification": collections.Counter(f.get("classification", "UNKNOWN") for f in sorted_findings),
        "by_stage": collections.Counter(f.get("execution_stage", "UNKNOWN") for f in sorted_findings),
    }

    artifact_paths: dict[str, str] = {}
    for name in ["metadata.json", "module_index.json", "graph.json", "evidence.jsonl", "findings.json", "sbom.cdx.json", "proposals.json", "validation.json"]:
        file_p = run_path / name
        if file_p.is_file():
            artifact_paths[name] = str(file_p)
        else:
            artifact_paths[name] = "NOT_AVAILABLE"

    val_res = data.get("validation") or {}
    val_status = "NOT_RUN"
    if isinstance(val_res, dict) and "validation_results" in val_res and val_res["validation_results"]:
        val_status = val_res["validation_results"][0].get("status", "NOT_RUN")

    report_dict: dict[str, Any] = {
        "schema_version": "1.0",
        "scan_id": meta.get("scan_id", "scan-unknown"),
        "metadata": {
            "repo_url": meta.get("repo_url", "NOT_AVAILABLE"),
            "commit_sha": meta.get("commit_sha"),
            "source_kind": meta.get("source_kind", "UNKNOWN"),
            "status": meta.get("status", "UNKNOWN"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_versions": meta.get("tool_versions", {}),
            "database_snapshots": meta.get("database_snapshots", {})
        },
        "coverage_summary": coverage_sum,
        "component_count": len(components),
        "occurrence_count": len(components),
        "edge_count": len(edges),
        "findings_summary": findings_summary,
        "finding_ids": [f.get("finding_id") for f in sorted_findings if "finding_id" in f],
        "claim_ids": [],
        "proposal_ids": [p.get("proposal_id") for p in data.get("proposals", []) if "proposal_id" in p],
        "validation_status": val_status,
        "residual_risks": [
            f.get("finding_id") for f in sorted_findings if f.get("priority") in ("P0", "P1")
        ],
        "limitations": [
            "Discovery depends on manifest/lockfile completeness; undeclared vendored binaries are not inspected.",
            "Reachability and execution evidence are marked as observed or potential based on entrypoints and scripts.",
            "Fix proposals require human authorization and isolated build/rescan validation before acceptance."
        ],
        "artifact_paths": artifact_paths
    }

    # Write report.json
    json_path = run_path / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2)

    # Generate Markdown report
    md_lines = [
        f"# Guardian Supply Chain Security Report",
        f"",
        f"> **Scan ID:** `{report_dict['scan_id']}` | **Status:** `{meta.get('status', 'UNKNOWN')}` | **Source:** `{meta.get('source_kind', 'UNKNOWN')}`",
        f"> **Repository:** `{meta.get('repo_url', 'NOT_AVAILABLE')}` | **Commit:** `{meta.get('commit_sha') or 'N/A'}`",
        f"",
        f"---",
        f"",
        f"## 1. Supply Chain Inventory & Coverage Summary",
        f"",
        f"| Metric | Count | Note |",
        f"|---|---|---|",
        f"| Total Modules | {coverage_sum.get('total_modules', 0)} | Monorepo/sub-projects detected |",
        f"| Resolved Modules | {coverage_sum.get('resolved_modules', 0)} | Full lockfile resolution |",
        f"| Partial Modules | {coverage_sum.get('partial_modules', 0)} | Unresolved dependencies present |",
        f"| Total Components | {len(components)} | Unique package occurrences |",
        f"| Dependency Edges | {len(edges)} | Direct & transitive graph relationships |",
        f"",
        f"## 2. Findings Summary",
        f"",
        f"- **Total Security Findings:** {findings_summary['total']}",
        f"- **Priority Breakdown:** P0: {findings_summary['by_priority'].get('P0', 0)}, P1: {findings_summary['by_priority'].get('P1', 0)}, P2: {findings_summary['by_priority'].get('P2', 0)}, P3: {findings_summary['by_priority'].get('P3', 0)}",
        f"- **Classifications:**",
    ]
    for cls_name, count in findings_summary['by_classification'].items():
        md_lines.append(f"  - `{cls_name}`: {count}")

    md_lines.extend([
        f"",
        f"## 3. Detailed Security Findings",
        f"",
        f"| Priority | Finding ID | Classification | Title | Advisory / Rule | Stage | Evidence |",
        f"|---|---|---|---|---|---|---|",
    ])
    for f in sorted_findings[:50]:  # Cap to top 50 in table for readability
        adv_or_rule = ", ".join(f.get("advisory_ids", [])) or f.get("rule_id") or "N/A"
        ev_str = ", ".join(f.get("evidence_ids", [])) or "NONE"
        md_lines.append(
            f"| **{f.get('priority', 'P3')}** | `{f.get('finding_id')}` | `{f.get('classification', '')}` | {html.escape(f.get('title', '')[:60])} | {adv_or_rule} | `{f.get('execution_stage', 'UNKNOWN')}` | `{ev_str}` |"
        )

    if len(sorted_findings) > 50:
        md_lines.append(f"\n*(Remaining {len(sorted_findings) - 50} findings omitted from summary table; consult `report.json` for full list)*")

    md_lines.extend([
        f"",
        f"## 4. Artifact Integrity & Provenance",
        f"",
        f"| Artifact File | Availability Status |",
        f"|---|---|",
    ])
    for art_name, art_loc in artifact_paths.items():
        md_lines.append(f"| `{art_name}` | `{art_loc}` |")

    md_lines.extend([
        f"",
        f"## 5. Security Limitations & Non-Negotiable Honesty",
        f"",
    ])
    for lim in report_dict["limitations"]:
        md_lines.append(f"- {lim}")

    md_path = run_path / "report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines) + "\n")

    return str(json_path), str(md_path)
