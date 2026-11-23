"""Self-tests for Role E's independent graph oracle and ground truth."""

from __future__ import annotations

import copy
import unittest
from pathlib import Path

from eval import graph_oracle as oracle

REPO = Path(__file__).resolve().parents[2]


def _comp(bundle, module_path, location):
    mid = next(m["module_id"] for m in bundle["modules"] if m["relative_path"] == module_path)
    for comp in bundle["components"]:
        if comp["module_id"] == mid and oracle.location_from_refs(comp["source_refs"]) == location:
            return comp
    raise AssertionError(f"{module_path}:{location} not in reference bundle")


class GroundTruthFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.truth = oracle.load_ground_truth(REPO / "ground_truth.yaml")

    def test_pinned_fixture_files_are_unchanged(self) -> None:
        for fixture_id in ("m1-oracle", "partial-failure", "a-sample-app"):
            with self.subTest(fixture=fixture_id):
                entry = oracle.find_fixture(self.truth, fixture_id)
                self.assertEqual(oracle.verify_fixture_files(entry, REPO), [])

    def test_deepest_dependency_is_not_imported_by_application_code(self) -> None:
        source = (REPO / "tests/fixtures/e_graph/m1-oracle/index.js").read_text(encoding="utf-8")
        for name in ("fx-beta", "fx-gamma", "fx-epsilon", "fx-peerhost"):
            self.assertNotIn(f'require("{name}")', source)

    def test_every_expected_edge_endpoint_is_an_expected_component(self) -> None:
        for fixture_id in ("m1-oracle", "partial-failure"):
            entry = oracle.find_fixture(self.truth, fixture_id)
            locations = {(c["module"], c["location"]) for c in entry["components"] if c.get("location")}
            for edge in entry["edges"]:
                if edge["from"] != oracle.ROOT:
                    self.assertIn((edge["module"], edge["from"]), locations)
                self.assertIn((edge["module"], edge["to"]), locations)


class OracleSensitivityTests(unittest.TestCase):
    def setUp(self) -> None:
        truth = oracle.load_ground_truth(REPO / "ground_truth.yaml")
        self.entry = oracle.find_fixture(truth, "m1-oracle")
        self.good = oracle.reference_bundle(self.entry)

    def _errors(self, bundle):
        return oracle.compare_graph(bundle, self.entry)["errors"]

    def test_reference_bundle_satisfies_ground_truth(self) -> None:
        for fixture_id in ("m1-oracle", "partial-failure"):
            truth = oracle.load_ground_truth(REPO / "ground_truth.yaml")
            entry = oracle.find_fixture(truth, fixture_id)
            report = oracle.compare_graph(oracle.reference_bundle(entry), entry)
            self.assertTrue(report["ok"], report["errors"])

    def test_missing_transitive_edge_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        alpha = _comp(bundle, ".", "node_modules/fx-alpha")["occurrence_id"]
        beta = _comp(bundle, ".", "node_modules/fx-beta")["occurrence_id"]
        bundle["edges"] = [e for e in bundle["edges"] if not (e["source_id"] == alpha and e["target_id"] == beta)]
        errors = self._errors(bundle)
        self.assertTrue(any("edge missing" in e for e in errors), errors)
        self.assertTrue(any("no path to node_modules/fx-gamma" in e for e in errors), errors)

    def test_invented_root_edge_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        root = next(m["module_id"] for m in bundle["modules"] if m["relative_path"] == ".")
        gamma = _comp(bundle, ".", "node_modules/fx-gamma")["occurrence_id"]
        bundle["edges"].append({**bundle["edges"][0], "edge_id": "edge:invented", "source_id": root, "target_id": gamma})
        errors = self._errors(bundle)
        self.assertTrue(any("invented edge" in e for e in errors), errors)
        self.assertTrue(any("shortest path to node_modules/fx-gamma" in e for e in errors), errors)

    def test_parent_invented_for_stray_component_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        root = next(m["module_id"] for m in bundle["modules"] if m["relative_path"] == ".")
        stray = _comp(bundle, ".", "node_modules/fx-stray")["occurrence_id"]
        bundle["edges"].append({**bundle["edges"][0], "edge_id": "edge:stray", "source_id": root, "target_id": stray})
        errors = self._errors(bundle)
        self.assertTrue(any("must_not: an observed edge points to node_modules/fx-stray" in e for e in errors), errors)

    def test_unreported_unresolved_declaration_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        bundle["warnings"] = [w for w in bundle["warnings"] if "fx-ghost" not in w]
        errors = self._errors(bundle)
        self.assertTrue(any("fx-ghost" in e and "not reported" in e for e in errors), errors)

    def test_declared_only_module_with_exact_version_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        api = next(m["module_id"] for m in bundle["modules"] if m["relative_path"] == "services/api")
        for comp in bundle["components"]:
            if comp["module_id"] == api:
                comp["resolved_version"] = "1.0.0"
        errors = self._errors(bundle)
        self.assertTrue(any("must_not" in e and "services/api" in e for e in errors), errors)

    def test_wrong_scope_and_directness_are_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        _comp(bundle, ".", "node_modules/fx-devtool")["dependency_scopes"] = ["production"]
        _comp(bundle, ".", "node_modules/fx-gamma")["directness"] = "DIRECT"
        errors = self._errors(bundle)
        self.assertTrue(any("fx-devtool" in e and "scope" in e for e in errors), errors)
        self.assertTrue(any("fx-gamma" in e and "directness" in e for e in errors), errors)

    def test_split_identity_for_shared_package_is_detected(self) -> None:
        bundle = copy.deepcopy(self.good)
        _comp(bundle, "services/worker", "node_modules/fx-beta")["package_key"] = "npm:fx-beta@2.1.0#other"
        errors = self._errors(bundle)
        self.assertTrue(any("different package_keys" in e for e in errors), errors)

    def test_missing_lockfile_pointer_falls_back_with_warning(self) -> None:
        bundle = copy.deepcopy(self.good)
        _comp(bundle, ".", "node_modules/fx-alpha")["source_refs"] = []
        report = oracle.compare_graph(bundle, self.entry)
        self.assertTrue(report["ok"], report["errors"])
        self.assertTrue(any("matched by unique name+version" in w for w in report["warnings"]))

    def test_failed_module_must_not_look_resolved(self) -> None:
        truth = oracle.load_ground_truth(REPO / "ground_truth.yaml")
        entry = oracle.find_fixture(truth, "partial-failure")
        bundle = oracle.reference_bundle(entry)
        broken = next(m for m in bundle["modules"] if m["relative_path"] == "services/broken")
        broken["coverage"], broken["coverage_reason"] = "RESOLVED", ""
        errors = oracle.compare_graph(bundle, entry)["errors"]
        self.assertTrue(any("services/broken" in e and "coverage" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
