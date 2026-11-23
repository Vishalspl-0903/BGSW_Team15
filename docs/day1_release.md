# Day 1 integrated release evidence

```yaml
release: day1-finalization-in-review
base_release_commit: c779db5660faebc5348aa3051d0f13fb417b97bf
base_release_tag: day1-integrated
finalization_branch: fix/day1-finalization
ci_status: PENDING_FINALIZATION_PR
green_ci_run_url: NOT_YET_AVAILABLE
local_dependency_install: PASS (PyYAML 6.0.3 resolved from ui/requirements.txt)
local_tests: 313 passed, 8 skipped, 40 subtests passed
local_release_checklist: PASS
contract_schema_version: '1.0'
members_merged: [A, B, C, D, E]
real_sample_repo: https://github.com/OWASP/NodeGoat
baseline_commit: 91d8adb963f5de15ccadc2b15a1b6aa67c624c4e
current_commit: c5cb68a7084e4ae7dcc60e6a98768720a81841e8
baseline_run_dir: runs/nodegoat-baseline/cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb
current_run_dir: runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
manifest_count: 1
module_count: 1
resolved_component_occurrences: 1479
package_identity_count: 1091
edge_count: 2296
confirmed_advisory_findings: 91
non_cve_rule_ids: [D5-UNPINNED-ACTION]
non_cve_findings: 6
ci_or_image_inspected: CI
coverage_status: RESOLVED
tests_passed: 313
tests_failed: 0
tests_skipped: 8
subtests_passed: 40
llm_mode: disabled
syft_version: 1.57.2
grype_version: 0.122.1
grype_database_built: '2026-11-23T06:28:32Z'
external_tools_unavailable: [trivy, osv-scanner]
reviewers: []
```

Both repository scans were static. Guardian did not install dependencies, run
NodeGoat scripts, build a container, or execute repository code. The current run
is `COMPLETE` and `validate-run` passes. Its canonical report is in the current
run directory above.

The Time Machine comparison used the same Grype database snapshot for both
commits. Measured differences are 13 added package occurrences, 8 in-place
version changes, 20 source/integrity record changes, 46 added dependency edges,
22 removed dependency edges and 5 bounded changed paths. Both commits have 91
confirmed advisory findings, so this comparison has zero newly observed
advisories. This does not establish runtime reachability or exploitability.

The eight skips are environment-gated cases: optional live scanner checks and
platform-specific symlink behavior. They are not counted as passing tests.

## Commands actually executed

```powershell
py -3.11 -m guardian.cli scan --repo https://github.com/OWASP/NodeGoat --ref 91d8adb963f5de15ccadc2b15a1b6aa67c624c4e --out runs/nodegoat-baseline
py -3.11 -m guardian.cli scan --repo https://github.com/OWASP/NodeGoat --ref c5cb68a7084e4ae7dcc60e6a98768720a81841e8 --out runs/nodegoat-current
py -3.11 -m guardian.cli validate-run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli report --run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli compare --baseline runs/nodegoat-baseline/cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb --current runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --out runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190/comparison.json
py -3.11 -m pytest -q
py -3.11 -m streamlit run ui/app.py
```

## Limits

- Source graph coverage reflects supported npm lockfile and Syft observations;
  Syft found 381 packages while the lockfile parser found 1,091 identities.
- No container image was built or inspected; CI is the required non-source surface.
- Findings are advisory and configuration evidence, not proof of exploitation.
- The old `day1-integrated` tag intentionally remains on the audited base commit.
- Finalization is not signed off until the repair PR is green and a human reviewer
  records the resulting merge commit and CI run URL.
