# Bosch Guardian — Day 1 Finalization and Release Repair

**Audit date:** 23 November 2026

**Repository:** `Vishalspl-0903/BGSW_Team15`

**Audited `main` and `day1-integrated` tag:** `c779db5660faebc5348aa3051d0f13fb417b97bf`

**Authoritative source:** Bosch official problem statement, page 4; `PROJECT_STATUS.md`; actual GitHub `main` files and saved NodeGoat run.
**Status:** Day 1 functionality is implemented and the local acceptance report records passing tests. **Final release CI is NOT GREEN yet.**

## 1. Mandatory Day 1 acceptance matrix

| Bosch milestone | Implementation | Evidence / intended demo |
|---|---|---|
| 1. Discover components | Implemented | NodeGoat: one npm module, 1,091 resolved package identities and 1,479 package occurrences; direct/transitive graph paths |
| 2. Build supply-chain view | Implemented | Syft source SBOM, `graph.json`, `graph.sqlite`, 2,296 evidence-backed dependency edges; CI workflows inspected (container not scanned) |
| 3. Detect vulnerabilities | Implemented | Grype database snapshot 2026-11-23T06:28:32Z; 91 advisory findings linked to exact package identities/occurrences and evidence |
| 4. Detect suspicious changes | Implemented at Bosch minimum | Six `D5-UNPINNED-ACTION` configuration indicators; Time Machine compares two commits, with 13 added occurrences, 8 in-place version changes, 20 changed source/integrity observations, 46 added and 22 removed edges |
| 5. Present evidence | Implemented | Streamlit `Dependency graph`, `Day 1 findings`, `Time Machine` views; source pointers, advisory URLs, uncertainty, `report.json`, `report.md`, comparison JSON |

**Limitations must remain explicit.** The six D5 warnings are configuration findings, **not evidence of malware**. The Time Machine's real NodeGoat comparison had **zero newly observed advisory findings** under a common Grype database snapshot; do not imply the changes introduced CVEs. `D1` baseline lockfile detector is `NOT_RUN` in the current scan; this does not invalidate the D5 implementation but must be disclosed. The source scan did not establish runtime reachability or inspect a built container.

## 2. P0 blocker — current GitHub CI fails

**Failing run:** `https://github.com/Vishalspl-0903/BGSW_Team15/actions/runs/45177800969`

**Job:** `Test Suite & Day 1 Release Verification`

**Failed step:** `Run unit & smoke tests`
**Cause:** `ModuleNotFoundError: No module named 'yaml'`, during collection of:
- `tests/c_guard/test_remediation_guard.py`
- `tests/e_advisory/test_e_vulns.py`
- `tests/e_detectors/test_e_d5_ci.py`

The workflow `.github/workflows/ci.yml` runs `pip install -r ui/requirements.txt pytest`. At the audited commit, `ui/requirements.txt` lists only `streamlit>=1.30` and `pydantic>=2.0`. However `guardian/guard.py`, `guardian/detectors/d5_ci.py` and ground-truth utilities use PyYAML.

**Minimal fix:** Add `PyYAML>=6.0,<7.0` to `ui/requirements.txt` (the existing workflow will install it). Do not weaken or skip the three tests. A ready-to-apply patch is provided as `day1_ci_pyyaml_fix.patch`.

**Test and merge discipline:**
1. Start a new branch from the actual current `main`, not from the old day1-dependency-graph branch.
2. Apply that minimal dependency fix; avoid unrelated code edits.
3. Run `python -m pip install -r ui/requirements.txt pytest`, then `python -m pytest -q` on a clean environment.
4. Run `python scripts/release_checklist.py` with the checked-in NodeGoat run.
5. Open PR into `main`. Let GitHub Actions finish; inspect all failures or skips and correct their causes rather than marking them green.
6. Human reviewer merges only after green CI. Record the new merge commit SHA; the old `day1-integrated` tag remains the old commit and should not be silently rewritten.

**Important:** This fix has not been run in this environment; the GitHub connection had read-only permission and local network access could not clone the repo. The patch is proposed, not applied.

## 3. P1 submission documentation corrections

**File `docs/demo-script.md` is stale.** It describes old UI tabs and old example findings; it also describes Day 2 candidate proposals and validation results as if verified, despite the Day 2 validator being explicitly blocked in `PROJECT_STATUS.md`. Replace with a script that matches the current three-view Streamlit UI and saved NodeGoat run. A corrected script is provided as `DAY1_JUDGE_DEMO_CORRECTED.md`.

**File `docs/day1_release.md` is stale.** It says `release: day1-integrated-candidate`, leaves `reviewers: []`, and states tagging remains to be done, while the actual annotated tag already points to `c779db...`. After merging the CI fix, update with the *new* reviewed commit SHA and actual green run URL. Do not invent reviewer names or rerun results.

**File `README.md` has outdated Day 2 capability wording and an outdated repository-tree example.** Label Day 2 as scaffolded/incomplete (not a completed working remediation loop) and point demo commands to the real baseline/current scan directories. Do not describe 196 old-branch advisories as the current 91 normalized Grype findings.

## 4. P2 consistency cleanup

The checked-in `runs/nodegoat-current/.../module_index.json` has per-module `scan_stage` entries `advisory=NOT_RUN` and `ci=NOT_RUN`, whereas `metadata.json` has scan-wide `advisory=COMPLETE`, `ci_workflow_policy=COMPLETE`. The Streamlit Day 1 view reads `metadata.stage_records`, so its displayed stage table is sourced from the completed scan, but consumers of `module_index.json` may be confused.

Resolve with one authoritative rule:
- Module-level discovery coverage is distinct from run-wide security-stage execution.
- If module `scan_stage` is intended to track those executions, synchronize it at pipeline completion and add a regression test.
- If not, clarify the semantics and name/describe the fields so `NOT_RUN` is not interpreted as contradicted by run-wide `COMPLETE`.
- Do not hand-edit an old hashed run artifact or silently replace evidence; generate a new verified run if an artifact format needs migration.

This cleanup is lower priority than green CI and accurate judge documentation.

## 5. Optional, *not required* for the Day 1 Bosch minimum

- Wire `--baseline-ref`/D1 lockfile suspicious-change detector into the normal scan if it is implemented, or document it as pending if absent.
- Add a reviewer-friendly link from changed Time Machine origin/integrity observations to the original source evidence.
- Capture a fully reproducible screen recording of the three-view UI and validate artifact downloads.

Do **not** delay the release to implement a new LLM, Docker image analysis, a second ecosystem or full Day 2 remediation. Bosch's Day 1 non-source-surface requirement is satisfied with CI workflow inspection.

## 6. Required final verification (Windows, repository root)

```powershell
git status --short
git rev-parse HEAD
py -3.11 -m pip install -r ui/requirements.txt pytest
py -3.11 -m pytest -q
py -3.11 scripts/release_checklist.py
py -3.11 -m guardian.cli validate-run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli graph --run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --summary
py -3.11 -m guardian.cli findings --run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli compare --baseline runs/nodegoat-baseline/cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb --current runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --out runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190/comparison.json
py -3.11 -m streamlit run ui/app.py
```

Run the equivalent `python` commands in Linux CI. Don't interpret skipped environment tests as passed, don't mark missing scanners as clean, and don't override exit codes. After CI succeeds on the final SHA, a human should inspect the PR and sign off. If the project requires a permanent final milestone tag, create a **new** `day1-final` tag pointing to the verified commit rather than force-moving `day1-integrated`.

## 7. Cold-start Codex instruction

> Audit repository `Vishalspl-0903/BGSW_Team15`, starting from the current `main` SHA and its `day1-integrated` tag, against the official Bosch Day 1 five-milestone brief, `project.md`, and `PROJECT_STATUS.md`. Do NOT rebuild or redesign the working graph, SBOM, Grype integration, CI detector, Streamlit views, Time Machine, or schemas. First inspect branch/worktree status, recent commits and full GitHub Actions run 45177800969. The first required fix is missing PyYAML: `guardian/guard.py` imports `yaml`, but CI installs only `ui/requirements.txt`, which lacks `PyYAML`. Add `PyYAML>=6.0,<7.0` to the reviewed runtime requirements and run the full tests in a clean environment. Then run `scripts/release_checklist.py` and the NodeGoat sample validation; address only actual reproducible failures. After the P0 gate passes, update the stale demo script and release document to reflect the real three-view app, actual commit tag, 91 Grype findings, 6 D5 findings, 1,479 occurrences/1,091 identities, 2,296 edges and Time Machine comparison. Remove fabricated or outdated Day 2 claims; Day 2 validation remains blocked. Check the module-index versus run-level stage-status discrepancy and fix or document it only with tests and immutable-artifact discipline. Open reviewable PRs; do not force-push main, rewrite release tags, run untrusted install scripts, or auto-merge. Capture exact test counts/skips, green CI run URL, final commit SHA, reviewer sign-off and a reproducible three-view demo. Declare Day 1 finished only when all five Bosch requirements are demonstrated from that exact final SHA and CI is green.
