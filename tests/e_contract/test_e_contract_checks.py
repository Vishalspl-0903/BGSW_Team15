"""Tests for Role E's independent contract and referential-integrity checks."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from eval import contract_checks as cc
from eval import graph_oracle as oracle

REPO = Path(__file__).resolve().parents[2]


def _finding(**overrides):
    base = {
        "schema_version": "1.0", "scan_id": "scan-e", "finding_id": "fnd:1",
        "finding_type": "VULNERABILITY", "title": "t", "description": "d",
        "module_ids": [], "occurrence_ids": [], "advisory_ids": ["GHSA-aaaa-bbbb-cccc"],
        "advisory_urls": [], "rule_id": None, "severity_label": "High", "cvss_score": 7.5,
        "priority": "P1", "evidence_ids": ["ev:1"], "dependency_path_node_ids": [],
        "path_status": "UNRESOLVED", "execution_stage": "UNKNOWN", "execution_evidence": "NOT_ANALYZED",
        "evidence_basis": "TOOL_OBSERVED", "uncertainties": [], "recommendations": [],
        "classification": "CONFIRMED_ADVISORY", "advisory_aliases": [], "first_seen_in": "REAL_UPSTREAM",
        "advisory_as_of": None, "scanner_names": ["grype"],
    }
    base.update(overrides)
    return base


class GraphBundleChecks(unittest.TestCase):
    def setUp(self) -> None:
        truth = oracle.load_ground_truth(REPO / "ground_truth.yaml")
        self.good = oracle.reference_bundle(oracle.find_fixture(truth, "m1-oracle"), scan_id="scan-e")

    def test_valid_bundle_passes(self) -> None:
        self.assertEqual(cc.check_graph_bundle(self.good, evidence_ids={"ev:fixture-lockfile"}), [])

    def test_dangling_edge_endpoint(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["edges"][0]["target_id"] = "occ:does-not-exist"
        self.assertTrue(any("target_id" in v for v in cc.check_graph_bundle(bad)))

    def test_observed_edge_without_evidence(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["edges"][0]["evidence_ids"] = []
        self.assertTrue(any("OBSERVED edge without evidence_ids" in v for v in cc.check_graph_bundle(bad)))

    def test_unknown_evidence_reference(self) -> None:
        self.assertTrue(any("does not exist" in v for v in cc.check_graph_bundle(self.good, evidence_ids={"ev:other"})))

    def test_constraint_mislabelled_as_resolved_version(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["components"][0]["resolved_version"] = "^1.0.0"
        self.assertTrue(any("looks like a constraint" in v for v in cc.check_graph_bundle(bad)))

    def test_resolved_without_version(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["components"][0]["resolved_version"] = None
        bad["components"][0]["package_key"] = None
        self.assertTrue(any("RESOLVED without resolved_version" in v for v in cc.check_graph_bundle(bad)))

    def test_image_claim_without_image_scan(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["components"][0]["image_presence"] = "NOT_OBSERVED_IN_SCANNED_IMAGE"
        self.assertTrue(any("no image was scanned" in v for v in cc.check_graph_bundle(bad)))

    def test_duplicate_ids_and_bad_summary(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["edges"].append(copy.deepcopy(bad["edges"][0]))
        bad["coverage_summary"]["resolved_modules"] = 99
        violations = cc.check_graph_bundle(bad)
        self.assertTrue(any("duplicate edge_id" in v for v in violations))
        self.assertTrue(any("resolved_modules" in v for v in violations))

    def test_non_resolved_module_needs_reason(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["modules"][1]["coverage_reason"] = ""
        self.assertTrue(any("coverage_reason" in v for v in cc.check_graph_bundle(bad)))

    def test_host_path_leak(self) -> None:
        bad = copy.deepcopy(self.good)
        bad["warnings"].append(r"read C:\Users\someone\project\package-lock.json")
        bad["warnings"].append("cache at /home/someone/.cache")
        self.assertEqual(len([v for v in cc.check_graph_bundle(bad) if "host path" in v]), 2)


class FindingAndEvidenceChecks(unittest.TestCase):
    def test_valid_finding_passes(self) -> None:
        self.assertEqual(cc.check_findings([_finding()], scan_id="scan-e", evidence_ids={"ev:1"}), [])

    def test_vulnerability_without_advisory_or_evidence(self) -> None:
        violations = cc.check_findings([_finding(advisory_ids=[], evidence_ids=[])])
        self.assertTrue(any("without advisory_ids" in v for v in violations))
        self.assertTrue(any("without evidence_ids" in v for v in violations))

    def test_malicious_classification_is_rejected(self) -> None:
        violations = cc.check_findings([_finding(classification="MALICIOUS")])
        self.assertTrue(any("classification" in v for v in violations))

    def test_rule_finding_needs_rule_id(self) -> None:
        f = _finding(finding_type="CI_POLICY", classification="CONFIGURATION_WEAKNESS", advisory_ids=[])
        self.assertTrue(any("without rule_id" in v for v in cc.check_findings([f])))

    def test_path_status_consistency(self) -> None:
        violations = cc.check_findings([_finding(path_status="FOUND"), _finding(finding_id="fnd:2", dependency_path_node_ids=["a"])])
        self.assertTrue(any("FOUND with an empty" in v for v in violations))
        self.assertTrue(any("although path_status" in v for v in violations))

    def test_mixed_scan_ids(self) -> None:
        self.assertTrue(any("scan_id" in v for v in cc.check_findings([_finding(scan_id="other")], scan_id="scan-e")))

    def test_evidence_records(self) -> None:
        good = {"schema_version": "1.0", "scan_id": "scan-e", "evidence_id": "ev:1", "kind": "ADVISORY",
                "tool_name": "grype", "tool_version": "0.0.0", "source_path": None, "json_pointer": "/matches/0",
                "line_start": None, "line_end": None, "observed_value": None, "raw_artifact": "raw/grype.json",
                "raw_sha256": "a" * 64, "observation": "match", "recorded_at": "2026-11-23T10:00:00Z"}
        self.assertEqual(cc.check_evidence_records([good], scan_id="scan-e"), [])
        bad = dict(good, evidence_id="ev:2", raw_sha256="XYZ", raw_artifact=r"C:\tmp\grype.json", recorded_at="yesterday")
        violations = cc.check_evidence_records([good, bad], scan_id="scan-e")
        self.assertTrue(any("raw_sha256" in v for v in violations))
        self.assertTrue(any("not relative" in v for v in violations))
        self.assertTrue(any("RFC3339" in v for v in violations))


class StageRecordChecks(unittest.TestCase):
    def test_complete_needs_count_and_failure_must_not_be_zero(self) -> None:
        ok = {"stage": "vulnerability_intelligence", "status": "COMPLETE", "known_matches": 0,
              "completed_at": "2026-11-23T10:00:00Z", "reason": None}
        self.assertEqual(cc.check_stage_record(ok), [])
        fake_zero = {"stage": "vulnerability_intelligence", "status": "UNAVAILABLE", "known_matches": 0,
                     "completed_at": None, "reason": "database not accessible"}
        self.assertTrue(any("known_matches as null" in v for v in cc.check_stage_record(fake_zero)))
        no_reason = {"stage": "x", "status": "FAILED", "known_matches": None, "reason": ""}
        self.assertTrue(any("without a reason" in v for v in cc.check_stage_record(no_reason)))


if __name__ == "__main__":
    unittest.main()
