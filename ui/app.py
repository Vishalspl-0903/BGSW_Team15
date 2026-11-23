"""Milestone 1 Streamlit dependency graph for the pinned NodeGoat scan."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from guardian import reporter
from guardian.analysis.paths import get_neighbors


def _dot_quote(value: object) -> str:
    return json.dumps(str(value), ensure_ascii=False)


def _node_label(node_id: str | None, components: dict, modules: dict) -> str:
    if node_id in modules:
        return f"Module {modules[node_id].get('relative_path', '.')}"
    component = components.get(node_id, {})
    name = component.get("name") or node_id or "Unknown package"
    version = component.get("resolved_version") or "Unresolved"
    return f"{name}@{version}"


st.set_page_config(page_title="Guardian Dependency Graph", layout="wide")

runs = sorted(
    (REPO_ROOT / "runs" / "nodegoat-m1").glob("*/metadata.json"),
    key=lambda path: path.stat().st_mtime,
    reverse=True,
)
run_dir = runs[0].parent if runs else REPO_ROOT / "runs" / "m1-demo"
data = reporter.load_run_data(run_dir)
metadata = data.get("metadata") or {}
graph = data.get("graph") or {}
components = graph.get("components") or []
modules = graph.get("modules") or []
edges = graph.get("edges") or []

st.title("NodeGoat Dependency Graph")

if not graph or not (run_dir / "graph.sqlite").is_file():
    st.info("The dependency graph is not ready yet.")
    st.stop()

component_map = {
    component["occurrence_id"]: component
    for component in components
    if component.get("occurrence_id")
}
module_map = {
    module["module_id"]: module
    for module in modules
    if module.get("module_id")
}

metric_packages, metric_edges, metric_modules = st.columns(3)
metric_packages.metric("Packages", len(components))
metric_edges.metric("Connections", len(edges))
metric_modules.metric("Modules", len(modules))

st.sidebar.header("Graph Controls")
search = st.sidebar.text_input("Search packages", placeholder="Package name or version").strip().casefold()
matches = [
    component
    for component in components
    if not search
    or search in str(component.get("name", "")).casefold()
    or search in str(component.get("resolved_version", "")).casefold()
]
center_options = list(module_map) + [
    component["occurrence_id"] for component in matches[:100]
]
if not center_options:
    st.info("No packages match this search.")
    st.stop()

center = st.sidebar.selectbox(
    "Center package",
    center_options,
    format_func=lambda node_id: _node_label(node_id, component_map, module_map),
)
depth = st.sidebar.slider("Depth", 1, 3, 2)
node_limit = st.sidebar.slider("Node limit", 10, 150, 50)

for sbom in sorted((run_dir / "sbom").glob("*.json")):
    st.sidebar.download_button(
        "Download SBOM",
        sbom.read_bytes(),
        file_name=sbom.name,
        mime="application/json",
    )

neighborhood = get_neighbors(
    str(run_dir / "graph.sqlite"),
    metadata["scan_id"],
    center,
    direction="both",
    depth=depth,
    max_nodes=node_limit,
)
visible_nodes = neighborhood.get("nodes", [])
visible_edges = neighborhood.get("edges", [])[:300]
visible_ids = {node.get("id") for node in visible_nodes}

if neighborhood.get("truncated"):
    st.info(
        f"Showing the first {node_limit} connected nodes. "
        "Search for a package to explore another area."
    )

st.caption(f"Showing {len(visible_nodes)} nodes and {len(visible_edges)} connections")

dot = [
    "digraph guardian_supply_chain {",
    'graph [rankdir="LR", bgcolor="transparent", pad="0.25", nodesep="0.55", ranksep="0.9", splines="polyline"];',
    'node [style="rounded,filled", fontname="Arial", fontsize="11", color="#cbd5e1", fontcolor="#f8fafc", margin="0.16,0.10"];',
    'edge [fontname="Arial", fontsize="9", color="#64748b", fontcolor="#334155", arrowsize="0.8"];',
]

for node in visible_nodes:
    node_id = str(node.get("id", ""))
    component = component_map.get(node_id)
    module = module_map.get(node_id)
    if module:
        label = f"MODULE  {module.get('relative_path', '.')}\n{module.get('ecosystem', 'unknown')}"
        fill, shape = "#2563eb", "folder"
        tooltip = f"Manifests: {', '.join(module.get('manifests', []))}\nLockfiles: {', '.join(module.get('lockfiles', []))}"
    elif component:
        version = component.get("resolved_version") or "Unresolved"
        directness = component.get("directness") or "Unknown"
        label = f"{component.get('name', 'Unknown package')}@{version}\n{directness}"
        fill = "#059669" if directness == "DIRECT" else "#7c3aed"
        shape = "box"
        tooltip = f"Source: {', '.join(component.get('source_refs', []))}\nEvidence: {', '.join(component.get('evidence_ids', []))}"
    else:
        label, fill, shape, tooltip = str(node.get("label", node_id)), "#475569", "box", node_id
    emphasis = ', penwidth="3", color="#f59e0b"' if node_id == center else ""
    dot.append(
        f"{_dot_quote(node_id)} [label={_dot_quote(label)}, tooltip={_dot_quote(tooltip)}, "
        f"shape={_dot_quote(shape)}, fillcolor={_dot_quote(fill)}{emphasis}];"
    )

for edge in visible_edges:
    source = str(edge.get("source_id", ""))
    target = str(edge.get("target_id", ""))
    if source not in visible_ids or target not in visible_ids:
        continue
    scope = edge.get("dependency_scope") or "dependency"
    evidence = ", ".join(edge.get("evidence_ids", []))
    dot.append(
        f"{_dot_quote(source)} -> {_dot_quote(target)} "
        f"[label={_dot_quote(scope)}, tooltip={_dot_quote(f'Evidence: {evidence}')}];"
    )

dot.append("}")
st.caption("Blue: module    Green: direct dependency    Purple: transitive dependency")
st.graphviz_chart("\n".join(dot), width="stretch")

st.subheader("Connection Details")
evidence_map = data.get("evidence", {})
rows = []
for edge in visible_edges:
    evidence_ids = edge.get("evidence_ids", [])
    records = [evidence_map[item] for item in evidence_ids if item in evidence_map]
    rows.append(
        {
            "From": _node_label(edge.get("source_id"), component_map, module_map),
            "To": _node_label(edge.get("target_id"), component_map, module_map),
            "Scope": edge.get("dependency_scope") or "dependency",
            "Source": "; ".join(
                f"{record.get('source_path') or record.get('raw_artifact') or 'Unavailable'}"
                f"{record.get('json_pointer') or ''}"
                for record in records
            ) or "Unavailable",
        }
    )

st.dataframe(rows, width="stretch", hide_index=True)
