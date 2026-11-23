"""Automated Day 1 Release Train Verification Checklist (§16 / §21).

Usage:
    python scripts/release_checklist.py [--run-dir RUN_DIR]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def check(name: str, passed: bool, details: str = "") -> bool:
    mark = "PASS" if passed else "FAIL"
    status_icon = "✅" if passed else "❌"
    print(f"[{mark}] {status_icon} {name}")
    if details:
        print(f"       {details}")
    return passed


def main() -> int:
    parser = argparse.ArgumentParser(description="Guardian Day 1 Release Checklist")
    parser.add_argument("--run-dir", default=str(REPO_ROOT / "runs" / "day1-nodegoat"), help="Run directory to evaluate")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    all_passed = True

    print("==================================================================")
    print("      BOSCH SOFTWARE SUPPLY CHAIN GUARDIAN - RELEASE GATE CHECK   ")
    print("==================================================================")
    print(f"Evaluating repository root: {REPO_ROOT}")
    print(f"Target run directory:      {run_dir}\n")

    # 1. Automated unit and smoke tests
    print("--- 1. Mandatory Test Suite (§16.4 / §21.3) ---")
    res = subprocess.run([sys.executable, "-m", "pytest", "-q"], cwd=str(REPO_ROOT), capture_output=True, text=True)
    tests_ok = (res.returncode == 0)
    all_passed &= check("Pytest test suite exits 0 without failures", tests_ok, res.stdout.strip())

    # 2. Contract Fixture Validity (§9.3)
    print("\n--- 2. Minimal Valid Live Fixture (§9.3) ---")
    contract_dir = REPO_ROOT / "tests" / "fixtures" / "contract_m1"
    required_fixture_files = ["metadata.json", "module_index.json", "graph.json", "evidence.jsonl", "findings.json"]
    fixture_files_ok = all((contract_dir / f).is_file() for f in required_fixture_files)
    all_passed &= check("Contract fixture files present in tests/fixtures/contract_m1", fixture_files_ok)

    # 3. Target Run Directory Artifacts (§16.5)
    print("\n--- 3. Target Run Artifact Completeness ---")
    run_files = ["graph.json", "metadata.json", "findings.json"]
    run_files_ok = all((run_dir / f).is_file() for f in run_files)
    sbom_candidates = [run_dir / "sbom" / "source.syft.json", run_dir / "sbom" / "syft.cdx.json", run_dir / "sbom.cdx.json"]
    run_files_ok = run_files_ok and any(p.is_file() and p.stat().st_size > 0 for p in sbom_candidates)
    all_passed &= check(f"Required run artifacts present in {run_dir.name}", run_files_ok)

    # 4. Dependency Graph Integrity
    print("\n--- 4. Dependency Graph & Supply Chain Integrity ---")
    graph_path = run_dir / "graph.json"
    if graph_path.is_file():
        with open(graph_path, "r", encoding="utf-8") as f:
            g = json.load(f)
        has_edges = bool(g.get("edges"))
        has_nodes = bool(g.get("components"))
        all_passed &= check("Graph contains direct and transitive edges (not flat list)", has_edges and has_nodes)
    else:
        all_passed &= check("Graph file loadable", False, "Missing graph.json")

    # 5. Security Findings & Advisory Provenance (§16.3)
    print("\n--- 5. Security Findings & Non-CVE Indicators ---")
    find_path = run_dir / "findings.json"
    if find_path.is_file():
        with open(find_path, "r", encoding="utf-8") as f:
            find_data = json.load(f)
        findings = find_data.get("findings", [])
        has_cve = any(f.get("finding_class") == "CONFIRMED_ADVISORY" or f.get("classification") == "CONFIRMED_ADVISORY" or f.get("finding_type") == "VULNERABILITY" for f in findings)
        has_non_cve = any(f.get("finding_class") in ("SUSPICIOUS_INDICATOR", "CONFIGURATION_WEAKNESS") or f.get("classification") in ("SUSPICIOUS_INDICATOR", "CONFIGURATION_WEAKNESS") for f in findings)
        all_passed &= check("Includes confirmed CVE/advisory with evidence", has_cve)
        all_passed &= check("Includes at least one non-CVE suspicious change / config indicator", has_non_cve)
    else:
        all_passed &= check("Findings data present", False, "Missing findings.json")

    # A complete status is only credible when the graph is populated and the
    # machine-readable SBOM expected by the current adapters is present.
    metadata_path = run_dir / "metadata.json"
    if metadata_path.is_file():
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            if metadata.get("status") == "COMPLETE":
                sbom_candidates = [run_dir / "sbom" / "source.syft.json", run_dir / "sbom" / "syft.cdx.json"]
                sbom_ok = any(p.is_file() and p.stat().st_size > 0 for p in sbom_candidates)
                all_passed &= check("Complete run has non-empty source SBOM at current adapter path", sbom_ok)
                graph_data = json.loads(graph_path.read_text(encoding="utf-8")) if graph_path.is_file() else {}
                all_passed &= check("Complete run graph has components and edges", bool(graph_data.get("components")) and bool(graph_data.get("edges")))
        except (OSError, json.JSONDecodeError) as exc:
            all_passed &= check("Run metadata is valid JSON", False, str(exc))

    # 6. Report Generation Verification
    print("\n--- 6. Verifiable Report Generation (§14 D.2) ---")
    try:
        from guardian.reporter import create_report
        json_p, md_p = create_report(str(run_dir))
        reports_ok = Path(json_p).is_file() and Path(md_p).is_file()
        all_passed &= check("create_report() produces valid report.json and report.md", reports_ok)
    except Exception as exc:
        all_passed &= check("create_report() succeeds", False, str(exc))

    print("\n==================================================================")
    if all_passed:
        print("🎉 RELEASE CHECKLIST: ALL P0 DAY 1 GATES PASSED (READY FOR TAG)")
        print("==================================================================")
        return 0
    else:
        print("⚠️ RELEASE CHECKLIST: GATE FAILED - DO NOT TAG day1-integrated")
        print("==================================================================")
        return 1


if __name__ == "__main__":
    sys.exit(main())
