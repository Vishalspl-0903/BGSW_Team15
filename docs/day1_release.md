# Day 1 Integration Status — Not Release Sign-off

**Status: M1 GRAPH DEMO VERIFIED; DAY 1 RELEASE NOT VERIFIED.** The integration
candidate suite and a controlled sample graph run passed locally. Advisory
scanning is blocked because Syft is unavailable. The historical NodeGoat run
below is invalid and must not be presented as evidence.

```yaml
release: M1_GRAPH_DEMO_ONLY
integration_branch: integrate/m1
checkout_commit: 72c0eda
main_commit: a0d081a (does not contain the role integrations)
contract_schema_version: '1.0'
members_merged: [A, B, C, D, E]
real_sample_repo: controlled sandbox/sample-app (local fixture; no untrusted code executed)
verified_demo_run: runs/m1-demo
verified_demo_scan_id: scan-ffff0b47d5cb447cb4f45bf7b1dedd60
verified_demo_status: PARTIAL
verified_demo_graph: 1 npm module, 2 occurrences, 2 edges (1 direct, 1 transitive)
verified_demo_transitive_path: mod:c3633b75a7648db82995c0ce -> occ:b17519514a58bc863afe65b4 -> occ:7c4a69d369238e657a5cced8
verified_demo_validation: PASS
scan_run_dir: runs/day1-nodegoat (INVALID FOR DEMO: graph arrays are empty; SBOM artifacts do not match current adapters)
manifest_count: UNVERIFIED
module_count: UNVERIFIED
resolved_component_count: UNVERIFIED
edge_count: UNVERIFIED
known_advisory_ids: []
non_cve_rule_ids: []
ci_or_image_inspected: UNVERIFIED
coverage_status: UNVERIFIED
tests_passed: 310
tests_failed: 0
tests_skipped: 8
subtests_passed: 40
llm_mode: disabled
external_tools_unavailable: [syft, grype]
limitations: [controlled local fixture only; advisory stage BLOCKED; no real repository scan; no main merge]
reviewers: []
```

## What is established
- The canonical contract fixture exists and explicitly labels its synthetic evidence.
- This integration candidate contains A, B, C, D, and E implementations.
- The candidate is not a verified M1 release or live demo until the required local checks pass.

## Required local verification
1. Install Python 3.11 or 3.12 and dependencies from `ui/requirements.txt`.
2. Run `python -m pytest -q` and retain the complete output.
3. Run `python -m guardian.cli validate-run tests/fixtures/contract_m1`.
4. Run a scan with Syft/Grype available; preserve the produced run directory and validate it with `python -m guardian.cli validate-run <run-dir>`.
5. Launch the UI and demonstrate that validated run. Do not select `runs/day1-nodegoat` until it is regenerated and validated.

