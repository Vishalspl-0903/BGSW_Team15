"""Tests for the D5 GitHub Actions workflow policy detector (Role E)."""

from __future__ import annotations

import hashlib
import inspect
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from eval import contract_checks as cc
from eval import graph_oracle as oracle
from guardian import detectors
from guardian.detectors import d5_ci

REPO = Path(__file__).resolve().parents[2]
TRUTH = oracle.load_ground_truth(REPO / "ground_truth.yaml")
CASES = {entry["id"]: entry for entry in TRUTH["detector_fixtures"]}


def _scan(case_id: str, run_dir: str | None = None) -> dict:
    return d5_ci.scan_workflows("e-d5", str(REPO / CASES[case_id]["path"]), run_dir)


def _evidence_by_id(result) -> dict:
    return {e["evidence_id"]: e for e in result["evidence"]}


class FixtureIntegrity(unittest.TestCase):
    def test_pinned_workflow_fixtures_are_unchanged(self) -> None:
        for case_id, entry in CASES.items():
            with self.subTest(case=case_id):
                self.assertEqual(oracle.verify_fixture_files(entry, REPO), [])


class GroundTruthCases(unittest.TestCase):
    def _check(self, case_id: str) -> dict:
        result = _scan(case_id)
        entry = CASES[case_id]
        self.assertEqual(result["stage"]["status"], entry["expected_stage"])
        got = {(f["rule_id"], f["title"]): f for f in result["findings"]}
        self.assertEqual(len(result["findings"]), len(entry["expected"]), [f["title"] for f in result["findings"]])
        evidence = _evidence_by_id(result)
        for exp in entry["expected"]:
            match = [f for (rule, title), f in got.items() if rule == exp["rule"] and exp["value"] in title]
            self.assertEqual(len(match), 1, f"{exp} -> {list(got)}")
            finding = match[0]
            if "line" in exp:
                lines = {evidence[e]["line_start"] for e in finding["evidence_ids"]}
                self.assertEqual(lines, {exp["line"]})
            if "ref_kind" in exp:
                self.assertIn(f"({exp['ref_kind']})", finding["title"])
            if "locations" in exp:
                self.assertEqual(len(finding["evidence_ids"]), exp["locations"])
        return result

    def test_positive_fixture(self) -> None:
        result = self._check("d5-positive")
        self.assertFalse(any("contents: write" in f["title"] for f in result["findings"]))

    def test_benign_controls_are_not_flagged(self) -> None:
        self._check("d5-benign")

    def test_edge_cases_partial_with_coverage_gap(self) -> None:
        result = self._check("d5-edge")
        self.assertFalse(any("never-seen" in f["title"] for f in result["findings"]))
        self.assertFalse(any("ignored-action" in f["title"] for f in result["findings"]))
        gap = next(f for f in result["findings"] if f["rule_id"] == "D5-UNPARSED-WORKFLOW")
        self.assertEqual((gap["finding_type"], gap["classification"]), ("COVERAGE_GAP", "COVERAGE_LIMITATION"))
        self.assertEqual(result["stage"]["files_failed"], 1)

    def test_no_workflows_is_not_run_not_clean(self) -> None:
        result = self._check("d5-none")
        self.assertIsNone(result["stage"]["known_matches"])
        self.assertEqual(cc.check_stage_record(result["stage"]), [])

    def test_role_a_sample_app_is_a_benign_control(self) -> None:
        entry = oracle.find_fixture(TRUTH, "a-sample-app")
        result = d5_ci.scan_workflows("e-d5", str(REPO / entry["path"]))
        self.assertEqual(result["stage"]["status"], "COMPLETE")
        self.assertEqual(result["findings"], [])
        self.assertTrue(any("declare no top-level permissions" in n for n in result["stage"]["notes"]))


class FindingQuality(unittest.TestCase):
    def test_findings_pass_contract_checks_and_are_honest(self) -> None:
        for case_id in ("d5-positive", "d5-edge"):
            result = _scan(case_id)
            ids = {e["evidence_id"] for e in result["evidence"]}
            self.assertEqual(cc.check_findings(result["findings"], scan_id="e-d5", evidence_ids=ids), [])
            self.assertEqual(cc.check_evidence_records(result["evidence"], scan_id="e-d5"), [])
            for f in result["findings"]:
                self.assertEqual(f["priority"], "NEEDS_REVIEW")
                self.assertIsNone(f["severity_label"])
                self.assertNotIn("malicious", f["title"].lower())
                self.assertTrue(f["uncertainties"])

    def test_github_owned_action_is_labelled(self) -> None:
        checkout = next(f for f in _scan("d5-positive")["findings"] if "actions/checkout@v4" in f["title"])
        self.assertTrue(any("GitHub-owned" in u for u in checkout["uncertainties"]))

    def test_raw_copy_is_hashed_and_relative(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = _scan("d5-positive", tmp)
            ev = result["evidence"][0]
            self.assertEqual(ev["raw_artifact"], "raw/ci/.github__workflows__release.yml")
            stored = (Path(tmp) / ev["raw_artifact"]).read_bytes()
            self.assertEqual(hashlib.sha256(stored).hexdigest(), ev["raw_sha256"])

    def test_module_ids_come_from_role_a_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "module_index.json").write_text(json.dumps({"modules": [
                {"module_id": "mod:x", "ci_files": [".github/workflows/release.yml"]}]}), encoding="utf-8")
            result = _scan("d5-positive", tmp)
            self.assertTrue(all(f["module_ids"] == ["mod:x"] for f in result["findings"]))

    def test_missing_pyyaml_is_unavailable(self) -> None:
        with mock.patch.object(d5_ci, "_yaml", return_value=None):
            result = _scan("d5-positive")
        self.assertEqual(result["stage"]["status"], "UNAVAILABLE")
        self.assertEqual(result["findings"], [])


class Classification(unittest.TestCase):
    def test_reference_kinds(self) -> None:
        cases = {
            "actions/checkout@" + "a" * 40: ("remote", "full-sha"),
            "actions/checkout@v4": ("remote", "version-tag"),
            "org/act@v1.2.3-beta.1": ("remote", "version-tag"),
            "org/act@main": ("remote", "branch-or-other"),
            "org/act@abc1234": ("remote", "short-sha"),
            "org/act": ("remote", "missing-ref"),
            "./local/action": ("local", None),
            "docker://alpine:3.19": ("docker-mutable", None),
            "docker://alpine@sha256:" + "b" * 64: ("docker-digest", None),
        }
        for value, (kind, ref_kind) in cases.items():
            with self.subTest(value=value):
                info = d5_ci.classify_uses(value)
                self.assertEqual(info["kind"], kind)
                self.assertEqual(info.get("ref_kind"), ref_kind)


class PublicContract(unittest.TestCase):
    def test_signature_matches_project_md_9_4(self) -> None:
        params = list(inspect.signature(detectors.detect_suspicious_changes).parameters)
        self.assertEqual(params, ["scan_id", "repo_dir", "baseline_ref", "run_dir"])

    def test_d1_without_baseline_is_not_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = detectors.run_detectors("e-d5", str(REPO / "tests/fixtures/e_ci/benign"), None, tmp)
        d1 = next(s for s in result["stages"] if s["stage"] == "lockfile_change_detection")
        self.assertEqual(d1["status"], "NOT_RUN")
        self.assertIn("baseline", d1["reason"])


if __name__ == "__main__":
    unittest.main()
