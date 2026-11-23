"""Tests for guardian.reporter and report generation."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from guardian import reporter


class ReporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[2]
        self.fixture_dir = self.root / "tests" / "fixtures" / "contract_m1"

    def test_load_contract_fixture_smoke(self) -> None:
        data = reporter.load_run_data(self.fixture_dir)
        self.assertTrue(data["is_fixture"])
        self.assertIsNotNone(data["metadata"])
        self.assertEqual(data["metadata"]["scan_id"], "scan-m1-fixture")
        self.assertIsNotNone(data["graph"])
        self.assertEqual(len(data["graph"]["components"]), 2)
        self.assertEqual(len(data["findings"]), 4)

    def test_create_report_generates_valid_json_and_md(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Copy fixture files to temp dir
            for item in ["metadata.json", "module_index.json", "graph.json", "findings.json", "evidence.jsonl"]:
                src = self.fixture_dir / item
                if src.is_file():
                    (tmp_path / item).write_text(src.read_text(encoding="utf-8"), encoding="utf-8")

            json_p, md_p = reporter.create_report(str(tmp_path))
            self.assertTrue(Path(json_p).is_file())
            self.assertTrue(Path(md_p).is_file())

            with open(json_p, "r", encoding="utf-8") as f:
                report = json.load(f)

            self.assertEqual(report["schema_version"], "1.0")
            self.assertEqual(report["component_count"], 2)
            self.assertEqual(report["edge_count"], 2)
            self.assertEqual(report["findings_summary"]["total"], 4)
            # Assert missing artifacts are labeled NOT_AVAILABLE, not blank success
            self.assertEqual(report["artifact_paths"]["sbom.cdx.json"], "NOT_AVAILABLE")

            # Verify markdown contains header and honesty limitations
            md_content = Path(md_p).read_text(encoding="utf-8")
            self.assertIn("Guardian Supply Chain Security Report", md_content)
            self.assertIn("Security Limitations & Non-Negotiable Honesty", md_content)

    def test_find_shortest_path_transitive(self) -> None:
        data = reporter.load_run_data(self.fixture_dir)
        path = reporter.find_shortest_path(data["graph"], "mod-root", "occ-qs-6.7.0")
        self.assertEqual(path, ["mod-root", "occ-express-4.17.1", "occ-qs-6.7.0"])

    def test_find_shortest_path_unconnected(self) -> None:
        data = reporter.load_run_data(self.fixture_dir)
        path = reporter.find_shortest_path(data["graph"], "mod-root", "occ-unconnected-does-not-exist")
        self.assertEqual(path, [])

    def test_bounded_neighborhood_caps_max_nodes(self) -> None:
        synth_dir = self.root / "tests" / "fixtures" / "synthetic_10000"
        if not synth_dir.is_dir():
            self.skipTest("synthetic_10000 fixture not present")
        data = reporter.load_run_data(synth_dir)
        nbrs = reporter.get_neighbors(data["graph"], "mod-synth-root", depth=2, max_nodes=50)
        self.assertLessEqual(nbrs["node_count"], 50)
        self.assertTrue(nbrs["truncated"])


if __name__ == "__main__":
    unittest.main()

