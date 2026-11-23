"""Test doubles for OTHER roles' public signatures (§9.4), used only by C's tests.

They let C's orchestration be tested before B/E merge, without implementing
B's graph builder or E's detectors in production code.  Everything they emit is
labelled SIMULATED/LOCAL_FIXTURE and validated against guardian.schemas.
"""

from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path

from guardian import cli
from guardian.schemas import (
    SCHEMA_VERSION, CoverageSummary, Evidence, Finding, FixAuditResult, GraphBundle, ProjectModule,
    ValidationResult, stable_id, utc_now,
)
from guardian.state import append_jsonl

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sandbox" / "sample-app"


def _evidence(run_dir: Path, scan_id: str, eid: str, kind: str, source: str, observation: str,
              observed=None) -> str:
    raw = run_dir / "repo" / source
    sha = hashlib.sha256(raw.read_bytes()).hexdigest() if raw.is_file() else None
    ev = Evidence(schema_version=SCHEMA_VERSION, scan_id=scan_id, evidence_id=eid, kind=kind,
                  tool_name="c-test-double", tool_version=None, source_path=source, json_pointer=None,
                  line_start=None, line_end=None, observed_value=observed,
                  raw_artifact=f"repo/{source}" if sha else None, raw_sha256=sha,
                  observation=f"SIMULATED (C test double): {observation}", recorded_at=utc_now())
    append_jsonl(run_dir / "evidence.jsonl", ev.to_json_dict())
    return eid


def fake_build_graph(scan_id: str, repo_dir: str, modules: list[ProjectModule]) -> GraphBundle:
    run_dir = Path(repo_dir).parent
    root = next(m for m in modules if m.ecosystem == "npm")
    mod = ProjectModule.model_validate({**root.to_json_dict(), "coverage": "RESOLVED", "coverage_reason": "",
                                        "scan_stage": {**root.scan_stage, "graph": "COMPLETE"}})
    lock = json.loads((Path(repo_dir) / "package-lock.json").read_text())
    ev_d = _evidence(run_dir, scan_id, "ev:lock-direct", "LOCKFILE", "package-lock.json", "root -> fixture-direct")
    ev_t = _evidence(run_dir, scan_id, "ev:lock-transitive", "LOCKFILE", "package-lock.json",
                     "fixture-direct -> fixture-transitive")
    common = {"declared_constraint": None, "source_refs": [], "resolution": "RESOLVED",
              "install_stage_indicator": None, "dependency_scopes": ["production"], "license": None,
              "artifact_hashes": [], "package_source_type": "REGISTRY", "resolved_source_url": None,
              "registry_host": None, "source_scope": "SOURCE", "image_presence": "NOT_CHECKED",
              "module_id": mod.module_id}
    comps = []
    for name, directness, ev in (("fixture-direct", "DIRECT", ev_d), ("fixture-transitive", "TRANSITIVE", ev_t)):
        ver = lock["packages"][f"node_modules/{name}"]["version"]
        comps.append({**common, "package_key": stable_id("pkg", "npm", name, ver), "ecosystem": "npm", "name": name,
                      "resolved_version": ver, "purl": f"pkg:npm/{name}@{ver}",
                      "occurrence_id": stable_id("occ", scan_id, mod.module_id, name), "evidence_ids": [ev],
                      "directness": directness, "manifest_refs": ["package.json"] if directness == "DIRECT" else []})
    e_common = {"relationship": "DEPENDS_ON", "module_id": mod.module_id, "resolution": "OBSERVED",
                "dependency_scope": "production", "declared_constraint": None, "source_scope": "SOURCE"}
    edges = [
        {**e_common, "edge_id": "edge:root-direct", "source_id": mod.module_id,
         "target_id": comps[0]["occurrence_id"], "evidence_ids": [ev_d]},
        {**e_common, "edge_id": "edge:direct-transitive", "source_id": comps[0]["occurrence_id"],
         "target_id": comps[1]["occurrence_id"], "evidence_ids": [ev_t]},
    ]
    return GraphBundle(schema_version=SCHEMA_VERSION, scan_id=scan_id, modules=[mod], components=comps,
                       edges=edges, coverage_summary=CoverageSummary.from_modules([mod]), warnings=[])


def advisory_finding(scan_id: str, graph: GraphBundle, ev_id: str, *, description: str = "SIMULATED advisory",
                     severity: str | None = "HIGH", priority: str = "P1") -> Finding:
    occ = graph.components[1]
    mod = graph.modules[0]
    return Finding.model_validate({
        "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "finding_id": stable_id("find", scan_id, "SIM-ADV-1"),
        "finding_type": "VULNERABILITY", "title": "fixture-transitive 2.0.0 matched SIM-ADV-0001 (SIMULATED)",
        "description": description, "module_ids": [mod.module_id], "occurrence_ids": [occ.occurrence_id],
        "advisory_ids": ["SIM-ADV-0001"], "advisory_urls": [], "rule_id": None, "severity_label": severity,
        "cvss_score": None, "priority": priority, "evidence_ids": [ev_id, *occ.evidence_ids],
        "dependency_path_node_ids": [mod.module_id, graph.components[0].occurrence_id, occ.occurrence_id],
        "path_status": "FOUND", "execution_stage": "RUNTIME", "execution_evidence": "NOT_ESTABLISHED",
        "evidence_basis": "TOOL_OBSERVED", "uncertainties": ["SIMULATED advisory for C orchestration tests"],
        "recommendations": ["upgrade fixture-transitive"], "classification": "CONFIRMED_ADVISORY",
        "advisory_aliases": [], "first_seen_in": "SEEDED_SIMULATION", "advisory_as_of": None,
        "scanner_names": ["c-test-double"],
    })


def install(monkeypatch, *, graph=True, vulns=True, detectors=True, vuln_description="SIMULATED advisory",
            vuln_fn=None, detect_fn=None, graph_fn=None) -> None:
    """Register fake role modules (or force them unavailable with None)."""
    def mod(name: str, **attrs):
        m = types.ModuleType(name)
        for k, v in attrs.items():
            setattr(m, k, v)
        monkeypatch.setitem(sys.modules, name, m)

    if graph:
        mod("guardian.analysis.graph_build", build_graph=graph_fn or fake_build_graph,
            write_graph_db=lambda g, p: Path(p).write_bytes(b""))
    else:
        monkeypatch.setitem(sys.modules, "guardian.analysis.graph_build", None)

    def default_vulns(scan_id, graph, run_dir):
        ev = _evidence(Path(run_dir), scan_id, "ev:adv-sim", "ADVISORY", "package-lock.json",
                       "SIM-ADV-0001 matched fixture-transitive@2.0.0", observed="SIM-ADV-0001")
        return [advisory_finding(scan_id, graph, ev, description=vuln_description)]

    def default_detect(scan_id, repo_dir, baseline_ref, run_dir):
        ev = _evidence(Path(run_dir), scan_id, "ev:ci-sim", "CI_CONFIG", ".github/workflows/static-check.yml",
                       "workflow inspected")
        return [Finding.model_validate({
            "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "finding_id": stable_id("find", scan_id, "D5"),
            "finding_type": "CI_POLICY", "title": "SIMULATED mutable action reference", "description": "SIMULATED",
            "module_ids": [], "occurrence_ids": [], "advisory_ids": [], "advisory_urls": [], "rule_id": "D5-sim",
            "severity_label": None, "cvss_score": None, "priority": "NEEDS_REVIEW", "evidence_ids": [ev],
            "dependency_path_node_ids": [], "path_status": "NOT_APPLICABLE", "execution_stage": "CI",
            "execution_evidence": "POTENTIAL", "evidence_basis": "RULE_MATCH", "uncertainties": [],
            "recommendations": [], "classification": "CONFIGURATION_WEAKNESS", "advisory_aliases": [],
            "first_seen_in": "SEEDED_SIMULATION", "advisory_as_of": None, "scanner_names": ["c-test-double"]})]

    if vulns:
        mod("guardian.adapters.vulns", scan_known_vulnerabilities=vuln_fn or default_vulns)
    else:
        monkeypatch.setitem(sys.modules, "guardian.adapters.vulns", None)
    if detectors:
        mod("guardian.detectors", detect_suspicious_changes=detect_fn or default_detect)
    else:
        monkeypatch.setitem(sys.modules, "guardian.detectors", None)
    monkeypatch.setenv("LLM_MODE", "disabled")


def scan(out: Path, src: Path = SAMPLE) -> int:
    return cli.main(["scan", "--local", str(src), "--out", str(out)])


def allow_audit(proposal, run_dir):
    return FixAuditResult(audit_result_id=stable_id("aud", proposal.proposal_id), proposal_id=proposal.proposal_id,
                          candidate_package_key=None, known_advisories=[], new_dependency_count=0,
                          install_script_indicators=[], integrity_indicators=[], behavior_checks=[],
                          blocking_issues=[], evidence_ids=[], verdict="ALLOW_REVIEW")


def reject_audit(proposal, run_dir):
    return FixAuditResult(audit_result_id=stable_id("aud", proposal.proposal_id), proposal_id=proposal.proposal_id,
                          candidate_package_key=None, known_advisories=["SIM-ADV-9"], new_dependency_count=3,
                          install_script_indicators=["postinstall (SIMULATED)"], integrity_indicators=[],
                          behavior_checks=[], blocking_issues=["candidate has known advisory (SIMULATED)"],
                          evidence_ids=[], verdict="REJECT")


class RecordingValidator:
    """Stands in for A's validate_approved_proposal; records whether it was invoked."""

    def __init__(self, status: str = "PASS", raises: Exception | None = None):
        self.calls: list[tuple] = []
        self.status = status
        self.raises = raises

    def __call__(self, scan_id, proposal_id, approved_event_id, run_dir):
        self.calls.append((scan_id, proposal_id, approved_event_id))
        if self.raises:
            raise self.raises
        run = Path(run_dir)
        ev = _evidence(run, scan_id, f"ev:val-{len(self.calls)}", "VALIDATION", "package.json", "SIMULATED build log")
        passed = self.status == "PASS"
        return ValidationResult(
            schema_version=SCHEMA_VERSION, scan_id=scan_id, proposal_id=proposal_id, worktree_id="wt-sim",
            approval_event_id=approved_event_id, status=self.status,
            commands=[{"argv": ["simulated-build"], "exit_code": 0 if passed else 1, "log_evidence_id": ev,
                       "duration_ms": 1}],
            build_passed=passed, tests_passed=passed, rescan_completed=passed, before_sbom_path=None,
            after_sbom_path="repo/package.json" if passed else None, removed_findings=[], new_findings=[],
            remaining_findings=[], warnings=[] if passed else ["SIMULATED build failure"],
            started_at=utc_now(), finished_at=utc_now())
