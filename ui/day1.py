"""Read-only Day 1 findings and provenance view over canonical run artifacts."""
from pathlib import Path
import json

import streamlit as st


def render_day1(data: dict, run_dir: Path) -> None:
    """Display observed findings, coverage, evidence and existing report downloads."""
    meta = data.get("metadata") or {}
    graph = data.get("graph") or {}
    st.subheader("Scan coverage")
    st.write(f"Scan status: {meta.get('status', 'NOT_RUN')}")
    if data.get("is_fixture"):
        st.info("Controlled fixture or cached snapshot; this is not a live upstream scan.")
    for warning in data.get("warnings", []):
        st.warning(warning)
    records = meta.get("stage_records", {})
    st.dataframe([
        {"Stage": name, "Status": record.get("status"), "Tool": record.get("tool"),
         "Reason": record.get("reason") or ""}
        for name, record in records.items()
    ], hide_index=True, width="stretch")
    for name in ("advisory", "ci"):
        record = records.get(name, {})
        if record.get("status") != "COMPLETE":
            st.warning(f"{name}: {record.get('status', 'NOT_RUN')}. Results are incomplete.")
    st.dataframe([
        {"Module": m.get("relative_path"), "Coverage": m.get("coverage"),
         "Reason": m.get("coverage_reason"), "Ecosystem": m.get("ecosystem")}
        for m in graph.get("modules", [])
    ], hide_index=True, width="stretch")
    for warning in graph.get("warnings", []):
        st.warning(warning)

    findings = sorted(data.get("findings", []), key=lambda f: (f.get("priority", "UNASSESSED"), f["finding_id"]))
    st.subheader("Findings")
    if not data.get("artifacts_on_disk", {}).get("findings.json"):
        st.warning("Findings: NOT_AVAILABLE")
    else:
        confirmed = [f for f in findings if f.get("classification") == "CONFIRMED_ADVISORY"]
        left, right = st.columns(2)
        left.metric("Package advisory findings", len(confirmed))
        right.metric("Other findings", len(findings) - len(confirmed))
    kind = st.selectbox("Classification", ["All"] + sorted({f.get("classification", "UNKNOWN") for f in findings}))
    filtered = [f for f in findings if kind == "All" or f.get("classification") == kind]
    if filtered:
        chosen = st.selectbox("Finding", range(len(filtered)), format_func=lambda i: f"{filtered[i]['priority']} · {filtered[i]['title']}")
        finding = filtered[chosen]
        # Text/code widgets escape repository-controlled markup.
        st.text(finding["description"])
        st.write({key: finding.get(key) for key in (
            "classification", "severity_label", "priority", "first_seen_in", "advisory_as_of",
            "execution_stage", "execution_evidence", "path_status")})
        comp = {c["occurrence_id"]: c for c in graph.get("components", [])}
        mods = {m["module_id"]: m for m in graph.get("modules", [])}
        st.text("Affected modules: " + ", ".join(mods.get(mid, {}).get("relative_path", mid) for mid in finding["module_ids"]))
        st.dataframe([
            {"Package": comp.get(oid, {}).get("name", oid), "Version": comp.get(oid, {}).get("resolved_version"),
             "Directness": comp.get(oid, {}).get("directness")}
            for oid in finding["occurrence_ids"]
        ], hide_index=True)
        labels = []
        for nid in finding.get("dependency_path_node_ids", []):
            c = comp.get(nid)
            labels.append(f"{c['name']}@{c['resolved_version']}" if c else f"Module {mods.get(nid, {}).get('relative_path', nid)}")
        st.text("Dependency path: " + (" → ".join(labels) or finding.get("path_status", "UNRESOLVED")))
        st.text("Advisory sources:\n" + "\n".join(finding.get("advisory_urls", [])))
        st.text("Uncertainties:\n" + "\n".join(finding.get("uncertainties", [])))
        st.text("Recommendations, not validated fixes:\n" + "\n".join(finding.get("recommendations", [])))
        st.subheader("Evidence")
        for eid in finding["evidence_ids"]:
            record = data.get("evidence", {}).get(eid)
            if record is None:
                st.error(f"Missing evidence: {eid}")
            else:
                with st.expander(eid):
                    st.json(record)
    elif data.get("artifacts_on_disk", {}).get("findings.json"):
        st.info("No recorded findings in this selection. Check stage coverage before drawing conclusions.")

    st.subheader("Export")
    for name in ("report.json", "report.md", "graph.json"):
        path = run_dir / name
        if path.is_file():
            st.download_button(f"Download {name}", path.read_bytes(), file_name=name)
        elif name.startswith("report"):
            st.caption(f"{name}: NOT_AVAILABLE — run the CLI report command.")
    with st.expander("Scan provenance"):
        st.json(meta)
    with st.expander("Event history"):
        path = run_dir / "events.jsonl"
        if path.is_file():
            st.json([json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])
