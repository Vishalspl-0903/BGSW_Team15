"""Guardian Supply Chain Decision System - Reviewer Interface.

Streamlit application owned by Role D (feat/d-ui-reporter).
Renders supply chain inventory, bounded dependency graph, evidence provenance,
Day 1 findings (advisories, suspicious indicators, configuration weaknesses, coverage gaps),
and Day 2 audited fix candidate validation.
"""

from __future__ import annotations

import html
import json
import math
import os
import sys
from pathlib import Path

# Add project root to sys.path so guardian package is importable
repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

import streamlit as st
from guardian import reporter

st.set_page_config(
    page_title="Guardian Supply Chain Decision System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling for high readability and security badges
st.markdown("""
<style>
    .reportview-container .main .block-container {
        max-width: 1400px;
        padding-top: 1.5rem;
        padding-bottom: 2rem;
    }
    .watermark-box {
        padding: 0.75rem 1rem;
        background-color: #fff3cd;
        border-left: 5px solid #ffc107;
        color: #856404;
        margin-bottom: 1rem;
        border-radius: 4px;
        font-weight: 500;
    }
    .badge-p0 { background-color: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-p1 { background-color: #fd7e14; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-p2 { background-color: #ffc107; color: black; padding: 2px 8px; border-radius: 4px; font-weight: bold; }
    .badge-p3 { background-color: #6c757d; color: white; padding: 2px 8px; border-radius: 4px; }
    .evidence-card {
        background-color: #f8f9fa;
        border: 1px solid #dee2e6;
        border-radius: 6px;
        padding: 1rem;
        margin-bottom: 0.75rem;
    }
</style>
""", unsafe_allow_html=True)


# Sidebar: Run Selection and Provenance
st.sidebar.title("🛡️ Guardian Scanner")
st.sidebar.markdown("**Supply Chain Security Reviewer UI**")

default_options = [
    "tests/fixtures/contract_m1 (Contract Fixture - T+30)",
    "runs/day1-nodegoat (Historical run - INVALID; do not present)",
    "tests/fixtures/synthetic_10000 (10k Node Scalability Fixture)",
    "Custom Run Directory..."
]

selected_preset = st.sidebar.selectbox("Select Scan Run", default_options)

if selected_preset.startswith("tests/fixtures/contract_m1"):
    active_run_dir = repo_root / "tests/fixtures/contract_m1"
elif selected_preset.startswith("runs/day1-nodegoat"):
    active_run_dir = repo_root / "runs/day1-nodegoat"
elif selected_preset.startswith("tests/fixtures/synthetic_10000"):
    active_run_dir = repo_root / "tests/fixtures/synthetic_10000"
else:
    custom_path_input = st.sidebar.text_input("Enter Run Directory Path", value=str(repo_root / "tests/fixtures/contract_m1"))
    active_run_dir = Path(custom_path_input)

# Load data
run_data = reporter.load_run_data(active_run_dir)
metadata = run_data.get("metadata") or {}
graph = run_data.get("graph") or {}
components = graph.get("components") or []
edges = graph.get("edges") or []
findings = run_data.get("findings") or []
modules = (run_data.get("module_index") or {}).get("modules") or graph.get("modules") or []
is_fixture = run_data.get("is_fixture", False)

if selected_preset.startswith("runs/day1-nodegoat"):
    st.error("This historical run is not valid for a demo: its graph and summary disagree, and the SBOM expected by the current scanner is missing. Regenerate and validate a run before presenting live findings.")

# Fixture Watermark (§14 D.1)
if is_fixture:
    st.markdown(
        f'<div class="watermark-box">⚠️ <strong>[FIXTURE WATERMARK]</strong> Displaying synthetic fixture data from <code>{active_run_dir.name}</code>. This is not a live repository scan. (Requirement §14 D.1)</div>',
        unsafe_allow_html=True
    )

# Sidebar Run Metadata
st.sidebar.markdown("---")
st.sidebar.markdown(f"**Scan ID:** `{metadata.get('scan_id', 'UNKNOWN')}`")
st.sidebar.markdown(f"**Status:** `{metadata.get('status', 'UNKNOWN')}`")
st.sidebar.markdown(f"**Source Kind:** `{metadata.get('source_kind', 'UNKNOWN')}`")
if metadata.get("repo_url"):
    st.sidebar.markdown(f"**Repository:** `{metadata.get('repo_url')}`")
if metadata.get("commit_sha"):
    st.sidebar.markdown(f"**Commit:** `{metadata.get('commit_sha')[:8]}`")
if metadata.get("started_at"):
    st.sidebar.markdown(f"**Scanned At:** `{metadata.get('started_at')[:19]}`")

st.sidebar.markdown("---")
st.sidebar.subheader("Run Artifacts On Disk")
for art, exists in run_data.get("artifacts_on_disk", {}).items():
    icon = "✅" if exists else "❌"
    st.sidebar.text(f"{icon} {art}")


# Header & KPI Metrics
st.title("Bosch Software Supply Chain Guardian")
st.caption("Evidence-first supply chain dependency discovery, risk analysis, and fix validation.")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Modules", len(modules))
col2.metric("Components", len(components))
col3.metric("Graph Edges", len(edges))
col4.metric("Security Findings", len(findings))
cov_sum = graph.get("coverage_summary", {})
resolved_cnt = cov_sum.get("resolved_modules", len(modules))
col5.metric("Resolved Coverage", f"{resolved_cnt}/{len(modules)} Modules")

# Navigation Tabs
tab_overview, tab_inventory, tab_graph, tab_findings, tab_remediation, tab_reports = st.tabs([
    "📊 Module Overview & Coverage",
    "📦 Component Inventory (Search)",
    "🕸️ Dependency Graph Explorer",
    "🛡️ Findings & Evidence (Day 1)",
    "🔧 Fix Audit & Approval (Day 2)",
    "📄 Reports & Export"
])


# ==========================================
# TAB 1: MODULE OVERVIEW & COVERAGE
# ==========================================
with tab_overview:
    st.header("Project Modules & Discovery Coverage")
    st.markdown("Honest coverage reporting: Modules with partial, unsupported or failed discovery are explicitly highlighted.")

    if not modules:
        st.info("No module index data available in this run.")
    else:
        mod_table = []
        for m in modules:
            fc = m.get("file_counts", {})
            mod_table.append({
                "Module ID": m.get("module_id"),
                "Relative Path": m.get("relative_path"),
                "Ecosystem": m.get("ecosystem"),
                "Coverage Status": m.get("coverage"),
                "Coverage Reason": m.get("coverage_reason") or "N/A",
                "Scanners": ", ".join(m.get("scanner_names", [])),
                "Files (Scanned/Found)": f"{fc.get('scanned', 0)} / {fc.get('found', 0)}"
            })
        st.dataframe(mod_table, use_container_width=True)

    st.subheader("Scanner Capabilities & Scope")
    col_sc1, col_sc2 = st.columns(2)
    with col_sc1:
        st.markdown("**Tool Versions:**")
        tools = metadata.get("tool_versions", {})
        if tools:
            st.json(tools)
        else:
            st.text("No tool version metadata recorded.")
    with col_sc2:
        st.markdown("**Database Snapshots:**")
        dbs = metadata.get("database_snapshots", {})
        if dbs:
            st.json(dbs)
        else:
            st.text("No database snapshot metadata recorded.")


# ==========================================
# TAB 2: COMPONENT INVENTORY (SEARCH & PAGINATED)
# ==========================================
with tab_inventory:
    st.header("Discovered Software Components")
    st.markdown("Searchable and paginated package inventory. Scalable up to 10,000+ components without freezing.")

    # Search and Filter Controls
    search_col1, search_col2, search_col3 = st.columns([3, 1, 1])
    search_query = search_col1.text_input("🔍 Search component by name or version", value="").strip().lower()
    scope_filter = search_col2.selectbox("Directness", ["All", "DIRECT", "TRANSITIVE"])
    ecosystem_filter = search_col3.selectbox("Ecosystem", ["All"] + sorted(list({c.get("ecosystem", "unknown") for c in components})))

    # Filter components
    filtered_components = components
    if search_query:
        filtered_components = [
            c for c in filtered_components
            if search_query in c.get("name", "").lower() or search_query in str(c.get("resolved_version", "")).lower()
        ]
    if scope_filter != "All":
        filtered_components = [c for c in filtered_components if c.get("directness") == scope_filter]
    if ecosystem_filter != "All":
        filtered_components = [c for c in filtered_components if c.get("ecosystem") == ecosystem_filter]

    st.caption(f"Showing {len(filtered_components)} matching components (out of {len(components)} total)")

    # Pagination: 50 items per page
    PAGE_SIZE = 50
    total_pages = max(1, math.ceil(len(filtered_components) / PAGE_SIZE))
    page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)
    start_idx = (page_num - 1) * PAGE_SIZE
    end_idx = min(start_idx + PAGE_SIZE, len(filtered_components))
    page_items = filtered_components[start_idx:end_idx]

    table_rows = []
    for c in page_items:
        table_rows.append({
            "Name": c.get("name"),
            "Version": c.get("resolved_version"),
            "Directness": c.get("directness"),
            "Ecosystem": c.get("ecosystem"),
            "License": c.get("license") or "UNKNOWN",
            "Occurrence ID": c.get("occurrence_id"),
            "Source Type": c.get("package_source_type", "REGISTRY")
        })
    st.dataframe(table_rows, use_container_width=True)

    # Component Detail Drill-down
    if page_items:
        st.subheader("Component Provenance & Traceable Path")
        selected_occ = st.selectbox(
            "Select component on current page to inspect provenance",
            [c.get("occurrence_id") for c in page_items],
            format_func=lambda x: next((f"{c.get('name')}@{c.get('resolved_version')} ({c.get('directness')})" for c in page_items if c.get('occurrence_id') == x), x)
        )
        selected_comp = next((c for c in components if c.get("occurrence_id") == selected_occ), None)
        if selected_comp:
            det_c1, det_c2 = st.columns(2)
            with det_c1:
                st.markdown(f"**Package:** `{selected_comp.get('name')}`")
                st.markdown(f"**Version:** `{selected_comp.get('resolved_version')}`")
                st.markdown(f"**PURL:** `{selected_comp.get('purl')}`")
                st.markdown(f"**Origin URL:** `{selected_comp.get('resolved_source_url') or 'N/A'}`")
                st.markdown(f"**Manifest References:** `{', '.join(selected_comp.get('manifest_refs', [])) or 'None'}`")
            with det_c2:
                st.markdown(f"**Directness:** `{selected_comp.get('directness')}`")
                st.markdown(f"**Resolution State:** `{selected_comp.get('resolution')}`")
                st.markdown(f"**Evidence IDs:** `{', '.join(selected_comp.get('evidence_ids', []))}`")
                hashes = selected_comp.get("artifact_hashes", [])
                st.markdown(f"**Artifact Digest:** `{hashes[0][:32] + '...' if hashes else 'NOT_RECORDED'}`")

            # Dependency path query from module root
            root_module_id = modules[0].get("module_id") if modules else "mod-root"
            path = reporter.find_shortest_path(graph, root_module_id, selected_comp.get("occurrence_id"))
            st.markdown("**Dependency Path to Root Module:**")
            if path:
                st.success(" ➔ ".join([f"`{node}`" for node in path]))
            else:
                st.warning("`NO_KNOWN_PATH` - Transitive connection could not be resolved from root module.")


# ==========================================
# TAB 3: DEPENDENCY GRAPH EXPLORER (BOUNDED)
# ==========================================
with tab_graph:
    st.header("Bounded Supply Chain Graph Explorer")
    st.markdown("Safe bounded neighborhood rendering. Never forces entire large graphs into browser memory.")

    graph_col1, graph_col2 = st.columns([2, 1])
    with graph_col1:
        center_options = [modules[0].get("module_id", "mod-root")] if modules else ["mod-root"]
        center_options.extend([c.get("occurrence_id") for c in components[:100]])
        center_node = st.selectbox("Select Center Node for Neighborhood", center_options)
    with graph_col2:
        max_depth = st.slider("Neighborhood Depth", min_value=1, max_value=3, value=1)
        node_limit = st.slider("Max Node Display Limit", min_value=10, max_value=150, value=50)

    neighborhood = reporter.get_neighbors(graph, center_node, direction="both", depth=max_depth, max_nodes=node_limit)

    if neighborhood.get("truncated"):
        st.warning(f"⚠️ Neighborhood exceeded {node_limit} nodes and was truncated for browser responsiveness.")

    st.markdown(f"**Discovered Neighborhood:** {neighborhood['node_count']} nodes, {neighborhood['edge_count']} edges.")

    # Adjacency and Path Breadcrumb Display
    st.subheader("Adjacency Fallback & Connection List")
    edge_list = []
    for e in neighborhood.get("edges", []):
        edge_list.append({
            "From": e.get("source_id"),
            "Relationship": e.get("relationship", "DEPENDS_ON"),
            "To": e.get("target_id"),
            "Scope": e.get("dependency_scope", "production"),
            "Evidence ID": ", ".join(e.get("evidence_ids", []))
        })
    st.dataframe(edge_list, use_container_width=True)


# ==========================================
# TAB 4: FINDINGS & EVIDENCE (DAY 1)
# ==========================================
with tab_findings:
    st.header("Security Findings & Evidence Provenance")
    st.markdown("Categorized security findings: Verified Advisories vs Suspicious Indicators vs Configuration Weaknesses vs Coverage Gaps.")

    if not findings:
        st.info("No security findings reported for this run (clean or inventory-only scan).")
    else:
        # Breakdown filters
        find_tab1, find_tab2, find_tab3, find_tab4 = st.tabs([
            "🛡️ Verified Advisories",
            "⚠️ Suspicious Indicators",
            "⚙️ Configuration Weaknesses",
            "🔍 Coverage Gaps"
        ])

        def render_findings_list(items, empty_msg):
            if not items:
                st.info(empty_msg)
                return
            for item in items:
                prio = item.get("priority", "P3")
                badge_class = f"badge-{prio.lower()}" if prio in ("P0", "P1", "P2", "P3") else "badge-p3"
                st.markdown(
                    f'<div class="evidence-card">'
                    f'<span class="{badge_class}">{prio}</span> '
                    f'<strong>{html.escape(item.get("title", "Untitled"))}</strong> <code>[{item.get("finding_id")}]</code><br>'
                    f'<p style="margin-top: 6px;">{html.escape(item.get("description", ""))}</p>'
                    f'<small><strong>Advisories:</strong> {", ".join(item.get("advisory_ids", [])) or "None"} | '
                    f'<strong>Affected Module:</strong> {", ".join(item.get("module_ids", []))} | '
                    f'<strong>Stage:</strong> {item.get("execution_stage", "UNKNOWN")} ({item.get("execution_evidence", "")}) | '
                    f'<strong>Basis:</strong> {item.get("evidence_basis", "UNKNOWN")}</small><br>'
                    f'<small><strong>Recommendations:</strong> {", ".join(item.get("recommendations", [])) or "None"}</small>'
                    f'</div>',
                    unsafe_allow_html=True
                )

        with find_tab1:
            advisories = [f for f in findings if f.get("classification") == "CONFIRMED_ADVISORY" or f.get("finding_type") == "VULNERABILITY"]
            render_findings_list(advisories, "No confirmed CVE/advisories found.")

        with find_tab2:
            indicators = [f for f in findings if f.get("classification") == "SUSPICIOUS_INDICATOR" or f.get("finding_type") == "SUSPICIOUS_CHANGE"]
            render_findings_list(indicators, "No suspicious changes or indicators detected.")

        with find_tab3:
            configs = [f for f in findings if f.get("classification") == "CONFIGURATION_WEAKNESS" or f.get("finding_type") == "CI_POLICY"]
            render_findings_list(configs, "No configuration or CI weaknesses detected.")

        with find_tab4:
            gaps = [f for f in findings if f.get("classification") == "COVERAGE_LIMITATION" or f.get("finding_type") == "COVERAGE_GAP"]
            render_findings_list(gaps, "No coverage gaps or scanner limitations recorded.")

    # Raw Evidence Explorer
    st.subheader("Raw Evidence Explorer (evidence.jsonl)")
    evidence_dict = run_data.get("evidence", {})
    if evidence_dict:
        selected_ev_id = st.selectbox("Select Evidence Record to Inspect", list(evidence_dict.keys()))
        ev_obj = evidence_dict[selected_ev_id]
        st.json(ev_obj)
    else:
        st.text("No raw evidence records found.")


# ==========================================
# TAB 5: FIX AUDIT & APPROVAL (DAY 2)
# ==========================================
with tab_remediation:
    st.header("Audited Remediation & Authentic Approval Control")
    st.markdown("Day 2 Brain & Shield: Audited upgrade candidates, Critic/Guard review, explicit human approval gate, and independent validation.")

    proposals = run_data.get("proposals", [])
    if not proposals:
        st.info("No remediation proposals present in this run.")
    else:
        for prop in proposals:
            st.subheader(f"Proposal: `{prop.get('proposal_id')}`")
            st.markdown(f"**Strategy:** `{prop.get('strategy')}` | **Target Module:** `{prop.get('target_module_id')}`")
            st.markdown(f"**Rationale:** {prop.get('rationale')}")
            st.markdown(f"**Proposed Version:** `{prop.get('proposed_version')}`")

            # Static Audit & Critic/Guard Verdict
            st.markdown("#### Critic & Guard Static Audit Results")
            audit_res = run_data.get("audit_results", [])
            matching_audit = next((a for a in audit_res if a.get("proposal_id") == prop.get("proposal_id")), None)
            if matching_audit:
                col_a1, col_a2 = st.columns(2)
                with col_a1:
                    st.markdown(f"**Audit Verdict:** `{matching_audit.get('verdict')}`")
                    st.markdown(f"**Integrity:** {matching_audit.get('integrity_indicators', ['N/A'])[0]}")
                with col_a2:
                    st.markdown(f"**Critic Verdict:** `{matching_audit.get('critic_verdict', 'CHALLENGE_PASSED')}`")
                    st.markdown(f"**Guard Policy:** `{matching_audit.get('guard_verdict', 'POLICY_PASS')}`")

            # Authentic Approval Gate (§14 D.3 / §21 G15)
            st.markdown("#### Human Authorization Gate")
            st.info("ℹ️ **[APPROVAL ENGINE: READ-ONLY]** Day 1/Day 2 handoff mode: The approval control requires an active state backend and proposal-hash verification (§14 D.3 / §21 G15). It cannot silently mark approval without audit validation.")

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                if st.button("Authorize Remediation Candidate", key=f"appr_{prop.get('proposal_id')}"):
                    st.error("State backend authorization handler not wired in this run directory. Action fail-closed as required by §14 D.3.")
            with col_btn2:
                if st.button("Reject Candidate", key=f"rej_{prop.get('proposal_id')}"):
                    st.warning("Candidate marked REJECTED in local session.")

    # Independent Validation Results
    st.markdown("---")
    st.subheader("Independent Worktree Validation Results (validation.json)")
    val_data = run_data.get("validation")
    if val_data and "validation_results" in val_data and val_data["validation_results"]:
        vr = val_data["validation_results"][0]
        v_col1, v_col2, v_col3 = st.columns(3)
        v_col1.metric("Validation Status", vr.get("status", "NOT_RUN"))
        v_col2.metric("Build & Tests", "PASSED" if vr.get("tests_passed") else "FAILED")
        v_col3.metric("Rescan Status", "COMPLETED" if vr.get("rescan_completed") else "INCOMPLETE")

        st.markdown(f"**Findings Removed by Fix:** `{', '.join(vr.get('removed_findings', [])) or 'None'}`")
        st.markdown(f"**Remaining Residual Risk Findings:** `{', '.join(vr.get('remaining_findings', [])) or 'None'}`")
    else:
        st.text("No validation execution results recorded for this run.")


# ==========================================
# TAB 6: REPORTS & EXPORT
# ==========================================
with tab_reports:
    st.header("Supply Chain Audit Reports & Artifact Export")
    st.markdown("Generate and download verifiable `report.json` and human-readable `report.md`.")

    if st.button("Generate Fresh Report Artifacts"):
        try:
            r_json, r_md = reporter.create_report(str(active_run_dir))
            st.success(f"Generated `{Path(r_json).name}` and `{Path(r_md).name}` successfully.")
        except Exception as e:
            st.error(f"Failed generating report: {e}")

    # Check if report.md exists to preview
    rep_md_path = active_run_dir / "report.md"
    rep_json_path = active_run_dir / "report.json"

    if rep_json_path.is_file():
        with open(rep_json_path, "r", encoding="utf-8") as f:
            st.download_button("📥 Download report.json", data=f.read(), file_name="report.json", mime="application/json")

    if rep_md_path.is_file():
        with open(rep_md_path, "r", encoding="utf-8") as f:
            md_text = f.read()
        st.download_button("📥 Download report.md", data=md_text, file_name="report.md", mime="text/markdown")
        st.markdown("### Report Preview")
        st.markdown(md_text)
    else:
        st.info("Click 'Generate Fresh Report Artifacts' above to generate `report.md`.")
