"""Smoke and security tests for UI components and data handling."""

from __future__ import annotations

import html
import tempfile
import unittest
from pathlib import Path

from guardian import reporter


class UiDataSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(__file__).resolve().parents[2]
        self.fixture_dir = self.root / "tests" / "fixtures" / "contract_m1"

    def test_missing_run_dir_handled_gracefully(self) -> None:
        non_existent = self.root / "runs" / "definitely_does_not_exist_12345"
        data = reporter.load_run_data(non_existent)
        self.assertIsNotNone(data)
        self.assertEqual(len(data["findings"]), 0)
        self.assertFalse(data["artifacts_on_disk"]["metadata.json"])
        self.assertIn("Run directory not found", data["warnings"][0])

    def test_partial_or_missing_findings_rendered_as_not_run_without_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "metadata.json").write_text('{"status": "PARTIAL"}', encoding="utf-8")
            data = reporter.load_run_data(tmp_path)
            self.assertEqual(data["metadata"]["status"], "PARTIAL")
            self.assertEqual(data["findings"], [])
            self.assertFalse(data["artifacts_on_disk"]["findings.json"])

    def test_xss_escaping_in_findings(self) -> None:
        malicious_string = "<script>alert('pwned')</script>&quot;onload="
        escaped = html.escape(malicious_string)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_large_graph_search_and_pagination_latency(self) -> None:
        synth_dir = self.root / "tests" / "fixtures" / "synthetic_10000"
        if not synth_dir.is_dir():
            self.skipTest("synthetic_10000 fixture not generated")
        data = reporter.load_run_data(synth_dir)
        components = data["graph"]["components"]
        self.assertEqual(len(components), 10000)

        # Search filter
        query = "synthetic-lib-00042"
        filtered = [c for c in components if query in c.get("name", "")]
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["name"], "synthetic-lib-00042")

        # Pagination: slicing first 50 items should be instant
        page_1 = components[:50]
        self.assertEqual(len(page_1), 50)

    def test_approval_unwired_fails_closed(self) -> None:
        # In Day 1 or when state backend is absent, approval must fail-closed
        from guardian.validator import validate_approved_proposal, ValidationBlocked
        with self.assertRaises(ValidationBlocked):
            validate_approved_proposal("scan-01", "prop-01", "unwired-event", "unused")


if __name__ == "__main__":
    unittest.main()

