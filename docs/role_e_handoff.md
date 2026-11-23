# Role E handoff: advisory findings, D5 detector, ground truth, QA

**Role:** E (vulnerability normalisation, non-CVE detection, ground truth, release QA)
**Branch:** `E` (spec name `feat/e-detectors-eval`), cut from `main` @ `a0d081a`
**Contract:** PROJECT.md v2.0, sections 9.4, 15, 17, 18, 21

Everything below runs **offline** and imports `guardian.schemas` only lazily: until C's contract is
merged, functions return plain dictionaries shaped like the frozen section 9 models; once
`guardian/schemas.py` exists, findings and evidence are validated into C's `Finding` / `Evidence` models.

## Files (all inside Role E's ownership; no other role's file was edited)

| Path | What it is |
|---|---|
| `guardian/adapters/vulns.py` | Grype on B's SBOM → canonical findings, evidence and a stage record |
| `guardian/analysis/advisory_normalizer.py` | Grype match parsing, alias grouping through scanner metadata only, initial priority |
| `guardian/detectors/__init__.py` | `detect_suspicious_changes()` contract + `run_detectors()` with stage records |
| `guardian/detectors/d5_ci.py` | D5 GitHub Actions workflow policy detector |
| `guardian/detectors/_common.py` | ids, timestamps, provenance, lazy schema validation |
| `ground_truth.yaml` | Hand-written expectations: graph, advisory and detector fixtures |
| `eval/graph_oracle.py` | Compares any `graph.json` with the ground truth (`python -m eval.graph_oracle`) |
| `eval/contract_checks.py` | Independent schema and referential-integrity checks (cross-check for `validate-run`) |
| `eval/gen_graph.py` | Deterministic synthetic graphs (100 / 1k / 10k) + baseline traversal timing |
| `eval/record_grype_fixture.py` | Re-records the offline Syft + Grype fixtures, with host paths removed |
| `tests/e_*` | 5 test packages (oracle, contract, advisory, detectors, eval) |
| `tests/fixtures/e_graph/` | M1 graph oracle fixture (multi-module) + partial-failure fixture |
| `tests/fixtures/e_advisory/` | Real npm versions with real advisories, clean control, recorded scans, hand-written graph |
| `tests/fixtures/e_ci/` | D5 positive / benign / edge / no-workflow fixtures |

## Public interfaces (PROJECT.md 9.4, unchanged signatures)

```python
from guardian.adapters.vulns import scan_known_vulnerabilities          # (scan_id, graph, run_dir) -> list[Finding]
from guardian.adapters.vulns import run_vulnerability_intelligence      # same + {"stage", "evidence"}
from guardian.detectors import detect_suspicious_changes                # (scan_id, repo_dir, baseline_ref, run_dir) -> list[Finding]
from guardian.detectors import run_detectors                            # same + {"stages", "evidence"}
```

Stage records follow section 18.3 (`stage, status, attempted, tool, tool_version, reason, completed_at,
known_matches, evidence_ids`) plus a few extra fields (`advisory_as_of`, `raw_matches`, `unmapped_matches`,
`sbom`, `files_found`, `files_scanned`, `files_failed`, `notes`). C: keep or drop the extras, but keep
`known_matches = null` for any non-COMPLETE status.

## What works (measured on this branch)

- **Known advisories (Grype 0.122.1, database built 2026-11-23T06:28:32Z):** the real-npm fixture gives
  5 findings: lodash 4.17.20 × 4 (GHSA-35jh-r3h4-6jhm / CVE-2021-23337, GHSA-29mw-wpgm-hmr9 / CVE-2020-28500,
  GHSA-r5fr-rjxr-66jc / CVE-2026-4800, GHSA-xxjr-mmjv-4gpg / CVE-2025-13465) and the **transitive**
  minimist 1.2.5 (GHSA-xvch-5gv4-984h / CVE-2021-44906), each mapped to its graph occurrence. The clean
  control gives `COMPLETE, known_matches 0`.
- **No fake zero:** missing SBOM → `BLOCKED`, missing Grype → `UNAVAILABLE`, database failure → `UNAVAILABLE`,
  bad output → `FAILED`; all with `known_matches = null` and no findings.
- **Alias rule:** ids merge only through Grype `relatedVulnerabilities`; same-title advisories stay separate;
  severity disagreements are reported, not resolved upwards.
- **D5:** 7 expected findings on the positive fixture (tag, semver tag, branch, short SHA, reusable workflow,
  docker tag, `write-all`), 0 on the benign control (full SHA, local action, digest, read-only, job-level single
  write scope), anchors handled, unparsable workflow → `COVERAGE_GAP` + stage `PARTIAL`, no workflows →
  `NOT_RUN`. Role A's `sandbox/sample-app` workflow is a benign control (0 findings).
- **Tests:** whole repository `84 passed, 2 skipped` (skips: Windows symlink permission in A's test; live
  Grype check without `GUARDIAN_GRYPE`). With `GUARDIAN_GRYPE` set: `85 passed, 1 skipped`.
- **Baseline traversal timing** (`python -m eval.gen_graph --nodes N --seed 7 --cycles 5 --measure`, this laptop):

| Occurrences | Edges | Index (ms) | BFS all modules (ms) | Peak traced MiB |
|---|---|---|---|---|
| 100 | 197 | 0.13 | 0.17 | 0.02 |
| 1,000 | 1,910 | 1.08 | 1.76 | 0.14 |
| 10,000 | 20,071 | ~11 | ~16 | 1.5 |

## Commands

```powershell
python -m pytest -q
$env:GUARDIAN_GRYPE = "<path to grype>"; python -m pytest -q tests/e_advisory     # adds the live Grype check
python -m eval.graph_oracle --graph runs/<id>/graph.json --fixture m1-oracle       # check B's graph
python -m eval.gen_graph --nodes 10000 --seed 7 --cycles 5 --measure
python -m eval.record_grype_fixture --fixture tests/fixtures/e_advisory/real-npm --out tests/fixtures/e_advisory/recorded/real-npm --syft <syft> --grype <grype>
```

Before a live scan, download the database once: `grype db update`. Scans run with
`GRYPE_DB_AUTO_UPDATE=false`, so they never update silently mid-run.

## Requests to other roles

- **C:**
  - Publish `guardian/schemas.py` (models `Finding`, `Evidence`, enums named as in 9.1).
  - Add `PyYAML` and `pytest` to the dev requirements (D5 and `ground_truth.yaml` need PyYAML).
  - The C orchestrator persists the `evidence` lists returned by E into `evidence.jsonl`.
- **B:**
  1. Write the source SBOM as `sbom/source.cdx.json` (or exactly one JSON file in `sbom/`).
  2. Put a lockfile pointer in each component's `source_refs`, e.g. `package-lock.json#/packages/node_modules~1fx-alpha`.
  3. Provide `graph.sqlite` and `get_dependency_path()` returning `{status, node_ids}`. Until then, advisory findings say `path_status: UNRESOLVED` with an explicit reason.
  4. Report declarations whose target is missing (`fx-ghost` in the oracle fixture).
  5. Run the oracle on `tests/fixtures/e_graph/m1-oracle`.
- **A:**
  - D5 reads `ci_files` from `module_index.json`.
  - `metadata.json` `source_kind` sets `first_seen_in`.
  - QA findings for A's code:
    - `docker-compose.yml` is not detected: the rule only matches names starting with `compose.`.
    - `acquire_repo()` has no test.
- **D:**
  - Add `runs/` and `__pycache__/` to `.gitignore`.
  - Gate commands are listed above.

## Known limits / not done

- D1 (lockfile baseline diff) not implemented: reported as `NOT_RUN` with a reason.
- Composite actions (`.github/actions/*/action.yml`) are not inspected yet.
- OSV as a second source is not wired. Only Grype is, per the 18.1 priority.
- Advisory findings do not compute paths themselves; they rely on B's query.
- Recorded advisory data is a dated snapshot. Newer databases may add advisories (the live test checks a superset).

**Merge-ready:** YES for E-owned files. Integration with C, B and A outputs is blocked until `schemas.py`, `graph.json` and `graph.sqlite` land on `main`.
