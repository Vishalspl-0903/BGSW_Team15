"""Tests for the Grype -> findings adapter and advisory normalisation (Role E)."""

from __future__ import annotations

import copy
import hashlib
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from eval import contract_checks as cc
from eval import graph_oracle as oracle
from guardian.adapters import vulns
from guardian.analysis import advisory_normalizer as norm

REPO = Path(__file__).resolve().parents[2]
REC = REPO / "tests/fixtures/e_advisory/recorded"
GRAPH = json.loads((REPO / "tests/fixtures/e_advisory/real-npm.graph.json").read_text(encoding="utf-8"))
TRUTH = oracle.load_ground_truth(REPO / "ground_truth.yaml")
ADV = {entry["id"]: entry for entry in TRUTH["advisory_fixtures"]}


def _report(name: str) -> dict:
    return json.loads((REC / name / "grype.json").read_text(encoding="utf-8"))


def _convert(report: dict, graph=GRAPH) -> dict:
    return vulns.findings_from_grype_report(
        "e-advisory-fixture", report, graph, raw_artifact="raw/grype/grype.json", raw_sha256="0" * 64,
        tool_version="0.122.1", advisory_as_of="2026-11-23T06:28:32Z", recorded_at="2026-11-23T10:00:00Z")


def _match(adv_id, name, version, related=(), severity="High", rel_severity=None):
    return {
        "vulnerability": {"id": adv_id, "dataSource": f"https://example.invalid/{adv_id}", "severity": severity,
                          "fix": {"versions": ["9.9.9"], "state": "fixed"}, "cvss": [], "description": "synthetic"},
        "relatedVulnerabilities": [{"id": r, "severity": rel_severity or severity, "dataSource": None} for r in related],
        "matchDetails": [{"type": "exact-direct-match"}],
        "artifact": {"name": name, "version": version, "type": "npm", "purl": f"pkg:npm/{name}@{version}",
                     "locations": [{"path": "/package-lock.json"}]},
    }


class RecordedFixtureIntegrity(unittest.TestCase):
    def test_manifest_hashes_match_recorded_files(self) -> None:
        for name in ("real-npm", "clean-npm"):
            manifest = json.loads((REC / name / "MANIFEST.json").read_text(encoding="utf-8"))
            for fname, digest in manifest["files"].items():
                with self.subTest(fixture=name, file=fname):
                    self.assertEqual(hashlib.sha256((REC / name / fname).read_bytes()).hexdigest(), digest)

    def test_recordings_contain_no_host_paths(self) -> None:
        for path in REC.rglob("*.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(cc.host_path_leaks(data), [], path.name)


class RealAdvisoryConversion(unittest.TestCase):
    def setUp(self) -> None:
        self.result = _convert(_report("real-npm"))
        self.findings = self.result["findings"]

    def test_expected_findings_match_ground_truth(self) -> None:
        expected = ADV["real-npm-grype"]["expected_findings"]
        got = {(f["advisory_ids"][0]): f for f in self.findings}
        self.assertEqual(len(self.findings), len(expected))
        for exp in expected:
            with self.subTest(advisory=exp["advisory_ids"][0]):
                f = got[exp["advisory_ids"][0]]
                self.assertEqual(f["advisory_ids"], exp["advisory_ids"])
                self.assertEqual(f["advisory_aliases"], exp["aliases"])
                self.assertEqual(f["severity_label"], exp["severity"])
                self.assertIn(f"{exp['package']}@{exp['version']}", f["title"])
                self.assertTrue(all(v in f["recommendations"][0] for v in exp["fixed_in"]))

    def test_controls_without_advisories_produce_no_findings(self) -> None:
        for pkg in ADV["real-npm-grype"]["expected_without_findings"]:
            self.assertFalse(any(pkg in f["title"] for f in self.findings), pkg)

    def test_transitive_match_maps_to_the_transitive_occurrence(self) -> None:
        minimist = next(f for f in self.findings if "minimist@1.2.5" in f["title"])
        self.assertEqual(minimist["occurrence_ids"], ["occ:e-adv-minimist"])
        self.assertEqual(minimist["module_ids"], ["mod:e-adv-root"])
        self.assertIn("ev:e-adv-lockfile", minimist["evidence_ids"])

    def test_findings_and_evidence_pass_independent_contract_checks(self) -> None:
        evidence_ids = {e["evidence_id"] for e in self.result["evidence"]} | {"ev:e-adv-lockfile"}
        self.assertEqual(cc.check_findings(self.findings, scan_id="e-advisory-fixture",
                                           evidence_ids=evidence_ids, graph=GRAPH), [])
        self.assertEqual(cc.check_evidence_records(self.result["evidence"], scan_id="e-advisory-fixture"), [])

    def test_honest_defaults(self) -> None:
        for f in self.findings:
            self.assertEqual(f["classification"], "CONFIRMED_ADVISORY")
            self.assertEqual(f["execution_evidence"], "NOT_ANALYZED")
            self.assertEqual(f["path_status"], "UNRESOLVED")
            self.assertTrue(any("not analyzed" in u for u in f["uncertainties"]))
            self.assertTrue(any("graph.sqlite" in u for u in f["uncertainties"]))
            self.assertEqual(f["advisory_as_of"], ADV["real-npm-grype"]["advisory_database_built"])
            self.assertNotEqual(f["priority"], "P0")

    def test_priority_mapping_from_published_severity(self) -> None:
        self.assertEqual(norm.initial_priority("Critical"), "P1")
        self.assertEqual(norm.initial_priority("High"), "P1")
        self.assertEqual(norm.initial_priority("Medium"), "P2")
        self.assertEqual(norm.initial_priority("Low"), "P3")
        self.assertEqual(norm.initial_priority(None), "NEEDS_REVIEW")
        self.assertEqual(norm.initial_priority("Unknown"), "NEEDS_REVIEW")

    def test_ids_are_stable_across_runs(self) -> None:
        again = _convert(_report("real-npm"))
        self.assertEqual([f["finding_id"] for f in self.findings], [f["finding_id"] for f in again["findings"]])

    def test_clean_report_yields_zero_findings(self) -> None:
        clean = _convert(_report("clean-npm"))
        self.assertEqual(clean["findings"], [])
        self.assertEqual(clean["raw_matches"], 0)


class AliasAndMappingRules(unittest.TestCase):
    def test_merge_only_through_scanner_alias_metadata(self) -> None:
        report = {"matches": [
            _match("SIM-ADV-A", "fx-pkg", "1.0.0", related=["SIM-CVE-1"]),
            _match("SIM-ADV-B", "fx-pkg", "1.0.0", related=["SIM-CVE-1"]),
            _match("SIM-ADV-C", "fx-pkg", "1.0.0"),
        ]}
        groups = norm.group_observations(norm.observations_from_grype(report))
        ids = sorted(tuple(g["advisory_ids"]) for g in groups)
        self.assertEqual(ids, [("SIM-ADV-A", "SIM-ADV-B"), ("SIM-ADV-C",)])
        merged = next(g for g in groups if "SIM-ADV-A" in g["advisory_ids"])
        self.assertEqual(merged["aliases"], ["SIM-CVE-1"])
        self.assertEqual(len(merged["observations"]), 2)

    def test_same_title_without_alias_link_is_not_merged(self) -> None:
        a, b = _match("SIM-ADV-D", "fx-pkg", "1.0.0"), _match("SIM-ADV-E", "fx-pkg", "1.0.0")
        b["vulnerability"]["description"] = a["vulnerability"]["description"]
        self.assertEqual(len(norm.group_observations(norm.observations_from_grype({"matches": [a, b]}))), 2)

    def test_same_advisory_on_two_packages_stays_separate(self) -> None:
        report = {"matches": [_match("SIM-ADV-F", "fx-one", "1.0.0"), _match("SIM-ADV-F", "fx-two", "1.0.0")]}
        self.assertEqual(len(norm.group_observations(norm.observations_from_grype(report))), 2)

    def test_duplicate_match_keeps_both_observations_as_evidence(self) -> None:
        report = {"matches": [_match("SIM-ADV-G", "lodash", "4.17.20"), _match("SIM-ADV-G", "lodash", "4.17.20")]}
        result = _convert(report)
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(len(result["evidence"]), 2)
        self.assertEqual(len([e for e in result["findings"][0]["evidence_ids"] if e != "ev:e-adv-lockfile"]), 2)

    def test_severity_conflict_is_reported_not_resolved(self) -> None:
        report = {"matches": [_match("SIM-ADV-H", "lodash", "4.17.20", related=["SIM-CVE-2"],
                                     severity="Medium", rel_severity="Critical")]}
        finding = _convert(report)["findings"][0]
        self.assertEqual(finding["severity_label"], "Medium")
        self.assertTrue(any("disagree on severity" in u for u in finding["uncertainties"]))

    def test_version_mismatch_is_coverage_gap_not_vulnerability(self) -> None:
        graph = copy.deepcopy(GRAPH)
        next(c for c in graph["components"] if c["name"] == "lodash")["resolved_version"] = "4.17.21"
        result = _convert({"matches": [_match("SIM-ADV-I", "lodash", "4.17.20")]}, graph)
        finding = result["findings"][0]
        self.assertEqual(finding["finding_type"], "COVERAGE_GAP")
        self.assertEqual(finding["classification"], "COVERAGE_LIMITATION")
        self.assertEqual(finding["evidence_basis"], "UNKNOWN")
        self.assertEqual(finding["priority"], "NEEDS_REVIEW")
        self.assertEqual(finding["occurrence_ids"], [])
        self.assertTrue(any("UNRESOLVED_COMPONENT" in u for u in finding["uncertainties"]))
        self.assertIn("coverage gap", finding["description"])
        self.assertEqual(result["unmapped_matches"], 1)

    def test_declared_only_components_are_coverage_gap(self) -> None:
        graph = copy.deepcopy(GRAPH)
        comp = next(c for c in graph["components"] if c["name"] == "lodash")
        comp.update(resolution="DECLARED_ONLY", resolved_version=None, package_key=None)
        finding = _convert({"matches": [_match("SIM-ADV-J", "lodash", "4.17.20")]}, graph)["findings"][0]
        self.assertEqual(finding["finding_type"], "COVERAGE_GAP")
        self.assertEqual(finding["classification"], "COVERAGE_LIMITATION")
        self.assertEqual(finding["occurrence_ids"], [])

    def test_purl_parsing(self) -> None:
        self.assertEqual(norm.parse_purl("pkg:npm/%40scope/name@1.2.3?package-id=x"), ("npm", "@scope/name", "1.2.3"))
        self.assertEqual(norm.parse_purl("pkg:golang/github.com/a/b@v1.0.0"), ("go", "github.com/a/b", "v1.0.0"))
        self.assertIsNone(norm.parse_purl("not-a-purl"))


class _FakeGrype:
    """Stands in for subprocess execution; never runs a real binary."""

    def __init__(self, scan_stdout: bytes = b"", scan_rc: int = 0, scan_stderr: bytes = b"", db_ok: bool = True):
        self.scan_stdout, self.scan_rc, self.scan_stderr, self.db_ok = scan_stdout, scan_rc, scan_stderr, db_ok
        self.calls: list[list[str]] = []

    def __call__(self, argv, env, timeout_s):
        self.calls.append(list(argv))
        assert env.get("GRYPE_DB_AUTO_UPDATE") == "false" and env.get("GRYPE_CHECK_FOR_APP_UPDATE") == "false"
        if argv[1] == "version":
            return subprocess.CompletedProcess(argv, 0, b'{"version": "0.122.1"}', b"")
        if argv[1] == "db":
            if not self.db_ok:
                return subprocess.CompletedProcess(argv, 1, b"", b"no vulnerability database")
            return subprocess.CompletedProcess(argv, 0, (REC / "real-npm/grype-db-status.json").read_bytes(), b"")
        return subprocess.CompletedProcess(argv, self.scan_rc, self.scan_stdout, self.scan_stderr)


class LiveStageStatus(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        (self.run_dir / "sbom").mkdir(parents=True)
        shutil.copy(REC / "real-npm/sbom.cdx.json", self.run_dir / "sbom/source.cdx.json")
        self.original_run = vulns._run

    def tearDown(self) -> None:
        vulns._run = self.original_run
        self.tmp.cleanup()

    def _scan(self, fake: _FakeGrype, **kwargs):
        vulns._run = fake
        return vulns.run_vulnerability_intelligence("e-live", GRAPH, str(self.run_dir),
                                                    grype_executable=sys.executable, **kwargs)

    def _assert_no_fake_zero(self, result, status):
        self.assertEqual(result["stage"]["status"], status)
        self.assertIsNone(result["stage"]["known_matches"])
        self.assertEqual(result["findings"], [])
        self.assertEqual(cc.check_stage_record(result["stage"]), [])

    def test_missing_sbom_is_blocked(self) -> None:
        shutil.rmtree(self.run_dir / "sbom")
        self._assert_no_fake_zero(self._scan(_FakeGrype()), "BLOCKED")

    def test_missing_grype_is_unavailable(self) -> None:
        result = vulns.run_vulnerability_intelligence("e-live", GRAPH, str(self.run_dir),
                                                      grype_executable=str(self.run_dir / "no-such-grype.exe"))
        self._assert_no_fake_zero(result, "UNAVAILABLE")

    def test_database_failure_is_unavailable_not_clean(self) -> None:
        result = self._scan(_FakeGrype(scan_rc=1, scan_stderr=b"failed to load vulnerability db", db_ok=False))
        self._assert_no_fake_zero(result, "UNAVAILABLE")

    def test_invalid_json_and_unknown_schema_fail(self) -> None:
        self._assert_no_fake_zero(self._scan(_FakeGrype(scan_stdout=b"not json")), "FAILED")
        self._assert_no_fake_zero(self._scan(_FakeGrype(scan_stdout=b'{"results": []}')), "FAILED")

    def test_completed_scan_writes_redacted_raw_and_findings(self) -> None:
        stdout = (REC / "real-npm/grype.json").read_bytes()
        result = self._scan(_FakeGrype(scan_stdout=stdout))
        stage = result["stage"]
        self.assertEqual(stage["status"], "COMPLETE")
        self.assertEqual(stage["known_matches"], 5)
        self.assertEqual(result["stage_details"]["advisory_as_of"], "2026-11-23T06:28:32Z")
        self.assertEqual(cc.check_stage_record(stage), [])
        raw = json.loads((self.run_dir / "raw/grype/grype.json").read_text(encoding="utf-8"))
        self.assertEqual(cc.host_path_leaks(raw), [])
        self.assertTrue(all(e["raw_artifact"] == "raw/grype/grype.json" for e in result["evidence"]))
        self.assertEqual(result["findings"][0]["first_seen_in"], "LOCAL_FIXTURE")

    def test_completed_clean_scan_is_complete_with_zero(self) -> None:
        stdout = (REC / "clean-npm/grype.json").read_bytes()
        stage = self._scan(_FakeGrype(scan_stdout=stdout))["stage"]
        self.assertEqual((stage["status"], stage["known_matches"]), ("COMPLETE", 0))

    def test_provenance_comes_from_metadata(self) -> None:
        (self.run_dir / "metadata.json").write_text(json.dumps({"source_kind": "GIT_PUBLIC"}), encoding="utf-8")
        stdout = (REC / "real-npm/grype.json").read_bytes()
        self.assertEqual(self._scan(_FakeGrype(scan_stdout=stdout))["findings"][0]["first_seen_in"], "REAL_UPSTREAM")

    def test_scanner_invocation_is_sbom_only(self) -> None:
        fake = _FakeGrype(scan_stdout=(REC / "clean-npm/grype.json").read_bytes())
        self._scan(fake)
        scan_call = next(c for c in fake.calls if c[1].startswith("sbom:"))
        self.assertIn("-o", scan_call)
        self.assertTrue(all(isinstance(a, str) for a in scan_call))


class PublicContract(unittest.TestCase):
    def test_signature_matches_project_md_9_4(self) -> None:
        params = list(inspect.signature(vulns.scan_known_vulnerabilities).parameters)
        self.assertEqual(params, ["scan_id", "graph", "run_dir"])

    def test_redaction(self) -> None:
        data = {"a": r"C:\Users\someone\cache\grype\db", "b": ["/home/someone/x", "keep me"], "c": 3}
        out = vulns.redact_host_paths(data, [(r"C:\Users\someone", "<home>")])
        self.assertEqual(out["a"], r"<home>\cache\grype\db")
        self.assertEqual(out["b"], ["<host-path>/x", "keep me"])
        self.assertEqual(cc.host_path_leaks(out), [])


@unittest.skipUnless(os.environ.get("GUARDIAN_GRYPE") and Path(os.environ.get("GUARDIAN_GRYPE", "")).is_file(),
                     "live Grype check needs GUARDIAN_GRYPE=<path to grype> with a downloaded database")
class LiveGrypeIntegration(unittest.TestCase):
    def test_real_grype_on_recorded_sbom(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "sbom").mkdir()
            shutil.copy(REC / "real-npm/sbom.cdx.json", run / "sbom/source.cdx.json")
            result = vulns.run_vulnerability_intelligence("e-live", GRAPH, str(run))
            self.assertEqual(result["stage"]["status"], "COMPLETE", result["stage"].get("reason"))
            found = {i for f in result["findings"] for i in f["advisory_ids"]}
            expected = {e["advisory_ids"][0] for e in ADV["real-npm-grype"]["expected_findings"]}
            self.assertTrue(expected <= found, expected - found)


if __name__ == "__main__":
    unittest.main()
