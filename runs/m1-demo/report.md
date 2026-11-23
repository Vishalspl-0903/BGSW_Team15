# Guardian Supply Chain Security Report

> **Scan ID:** `scan-ffff0b47d5cb447cb4f45bf7b1dedd60` | **Status:** `PARTIAL` | **Source:** `LOCAL_FIXTURE`
> **Repository:** `local://fixture/sandbox/sample-app` | **Commit:** `N/A`

---

## 1. Supply Chain Inventory & Coverage Summary

| Metric | Count | Note |
|---|---|---|
| Total Modules | 1 | Monorepo/sub-projects detected |
| Resolved Modules | 1 | Full lockfile resolution |
| Partial Modules | 0 | Unresolved dependencies present |
| Total Components | 2 | Unique package occurrences |
| Dependency Edges | 2 | Direct & transitive graph relationships |

## 2. Findings Summary

- **Total Security Findings:** 0
- **Priority Breakdown:** P0: 0, P1: 0, P2: 0, P3: 0
- **Classifications:**

## 3. Detailed Security Findings

| Priority | Finding ID | Classification | Title | Advisory / Rule | Stage | Evidence |
|---|---|---|---|---|---|---|

## 4. Artifact Integrity & Provenance

| Artifact File | Availability Status |
|---|---|
| `metadata.json` | `C:\Users\dthun\Documents\BoschHackathon\runs\m1-demo\metadata.json` |
| `module_index.json` | `C:\Users\dthun\Documents\BoschHackathon\runs\m1-demo\module_index.json` |
| `graph.json` | `C:\Users\dthun\Documents\BoschHackathon\runs\m1-demo\graph.json` |
| `evidence.jsonl` | `C:\Users\dthun\Documents\BoschHackathon\runs\m1-demo\evidence.jsonl` |
| `findings.json` | `C:\Users\dthun\Documents\BoschHackathon\runs\m1-demo\findings.json` |
| `sbom.cdx.json` | `NOT_AVAILABLE` |
| `proposals.json` | `NOT_AVAILABLE` |
| `validation.json` | `NOT_AVAILABLE` |

## 5. Security Limitations & Non-Negotiable Honesty

- Discovery depends on manifest/lockfile completeness; undeclared vendored binaries are not inspected.
- Reachability and execution evidence are marked as observed or potential based on entrypoints and scripts.
- Fix proposals require human authorization and isolated build/rescan validation before acceptance.
