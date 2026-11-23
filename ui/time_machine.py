"""Streamlit rendering for bounded supply-chain run comparisons."""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from guardian.analysis.time_machine import ComparisonError, compare_runs


def _label(path: tuple | list) -> str:
    if path[0] == "module":
        return f"Module {path[1]}"
    package_key = path[-1] or "unresolved package"
    return str(package_key).removeprefix("npm:")


def _table_rows(key: str, items: list[dict]) -> list[dict]:
    """Flatten nested comparison records for stable Arrow/dataframe rendering."""
    if key in ("added_edges", "removed_edges"):
        return [{"From": _label(item["from"]), "To": _label(item["to"]),
                 "Relationship": item["relationship"], "Scope": item["scope"]} for item in items]
    if key == "changed_sources":
        return [{"Package": item["package"], "Module": item["module"],
                 "Before": json.dumps(item["before"], sort_keys=True),
                 "After": json.dumps(item["after"], sort_keys=True),
                 "Location": "; ".join(item["source_refs"])} for item in items]
    if key in ("new_advisories", "removed_advisories"):
        return [{"Priority": item.get("priority"), "Title": item.get("title"),
                 "Advisories": ", ".join(item.get("advisory_ids", [])),
                 "Affected occurrences": len(item.get("occurrence_ids", []))} for item in items]
    rows = []
    for item in items:
        rows.append({name: "; ".join(value) if isinstance(value, list) else value
                     for name, value in item.items()})
    return rows


def render_time_machine(run_dirs: list[Path]) -> None:
    """Let a reviewer compare two already-scanned commits without rescanning in UI."""
    st.subheader("Supply Chain Time Machine")
    if len(run_dirs) < 2:
        st.info("Two completed scans of the same repository are required.")
        return
    labels = {}
    for run in run_dirs:
        try:
            meta = json.loads((run / "metadata.json").read_text(encoding="utf-8"))
            label = f"{meta.get('commit_sha') or meta.get('scan_id')} | {run.parent.name}"
            labels[label] = run
        except (OSError, ValueError):
            continue
    options = list(labels)
    if len(options) < 2:
        st.info("Two readable completed scans are required.")
        return
    baseline_label = st.selectbox("Baseline commit", options, index=min(1, len(options) - 1))
    current_label = st.selectbox("Current commit", options, index=0)
    if baseline_label == current_label:
        st.info("Choose two different scan runs.")
        return
    try:
        delta = compare_runs(labels[baseline_label], labels[current_label])
    except ComparisonError as exc:
        st.error(str(exc))
        return

    baseline, current = delta["baseline"], delta["current"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Package identities", current["package_identities"], current["package_identities"] - baseline["package_identities"])
    c2.metric("Occurrences", current["occurrences"], current["occurrences"] - baseline["occurrences"])
    c3.metric("Advisory findings", current["confirmed_advisories"], current["confirmed_advisories"] - baseline["confirmed_advisories"])
    snapshot = delta["advisory_snapshot"]
    if snapshot["code_change_attribution_allowed"]:
        st.success("Both commits were checked against the same advisory snapshot.")
    else:
        st.warning(delta["vulnerability_attribution"])

    changes = delta["changes"]
    st.subheader("Detected changes")
    categories = [
        ("Added packages", "added_packages"), ("Removed packages", "removed_packages"),
        ("Upgrades or downgrades", "upgraded_packages"), ("Changed origins", "changed_sources"),
        ("Added dependency relations", "added_edges"), ("Removed dependency relations", "removed_edges"),
        ("New advisory observations", "new_advisories"), ("Removed advisory observations", "removed_advisories"),
    ]
    for title, key in categories:
        with st.expander(f"{title} | {len(changes[key])}"):
            if changes[key]:
                st.dataframe(_table_rows(key, changes[key]), hide_index=True, width="stretch")
            else:
                st.caption("No changes in this category.")

    st.subheader("Changed dependency paths")
    paths = changes["changed_paths"]
    if paths:
        dot = ["digraph changes {", 'graph [rankdir="LR", bgcolor="transparent"];',
               'node [shape="box", style="rounded,filled", fillcolor="#fff7ed", color="#f97316"];',
               'edge [color="#f97316"];']
        seen = set()
        for path in paths:
            for node in path:
                node_id = json.dumps(repr(node))
                if node_id not in seen:
                    dot.append(f"{node_id} [label={json.dumps(_label(node))}];")
                    seen.add(node_id)
            for source, target in zip(path, path[1:]):
                dot.append(f"{json.dumps(repr(source))} -> {json.dumps(repr(target))};")
        dot.append("}")
        st.graphviz_chart("\n".join(dot), width="stretch")
        st.caption("Only paths containing an added package or newly observed advisory are drawn.")
    else:
        st.info("No changed dependency path is available for this comparison.")
    st.download_button("Download comparison JSON", json.dumps(delta, indent=2).encode(),
                       file_name="supply-chain-comparison.json", mime="application/json")
