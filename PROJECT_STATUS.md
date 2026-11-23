# Bosch Software Supply Chain Guardian — Project Status

**Status date:** 23 November 2026

**Repository:** `Vishalspl-0903/BGSW_Team15`

**Release branch:** `main`

**Release commit:** `c779db5660faebc5348aa3051d0f13fb417b97bf`

**Release tag:** `day1-integrated`

**Contract version:** `1.0`
**Current result:** Milestone 1 and Day 1 functionality are implemented. A finalization
repair is in progress because the audited GitHub Actions run for the original tag
failed to install PyYAML; local gates pass, but final CI and human review are still
required before declaring the repaired release final.

## 1. Executive summary

Guardian is an evidence-first software supply-chain scanner. It accepts an approved
public GitHub repository or controlled local fixture, pins the source revision,
detects project modules, produces a source SBOM, builds a normalized dependency
graph, attaches evidence to graph relationships, scans resolved packages for known
advisories, checks GitHub Actions configuration, assigns deterministic initial
priorities, and exports machine-readable and readable reports.

The integrated release was exercised on the official OWASP NodeGoat repository.
The scanner did not install NodeGoat dependencies, run lifecycle scripts, start the
application, or build its container. All repository inspection was static.

The release also contains a Supply Chain Time Machine. It compares two canonical
scan runs from the same repository and reports package, version, origin, dependency
edge and advisory changes. It draws only bounded changed paths rather than trying
to render the entire graph.

The audited base release is available on `origin/main`. The five role branches A–E
are integrated into that branch and tagged `day1-integrated`. The tag remains on
the audited base commit and will not be rewritten. Finalization changes are being
prepared on `fix/day1-finalization` for review.

### Finalization repair status

- Added `PyYAML>=6.0,<7.0` to the requirements installed by GitHub Actions.
- Replaced the stale demo script with the real three-view NodeGoat demonstration.
- Corrected README Day 2 claims and saved-run paths.
- Added future-scan synchronization between run-wide advisory/CI results and
  applicable module `scan_stage` fields, with a regression test.
- Preserved the old hashed scan artifacts; they were not hand-edited.
- Local full suite and release checklist pass. GitHub CI and human review remain
  pending until the finalization PR is opened and checked.

## 2. Current release evidence

### Verified NodeGoat source revisions

| Purpose | Git commit | Scan ID | Run directory |
|---|---|---|---|
| Time Machine baseline | `91d8adb963f5de15ccadc2b15a1b6aa67c624c4e` | `cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb` | `runs/nodegoat-baseline/cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb` |
| Current Day 1 demonstration | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` | `b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190` | `runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190` |

Both scans used Grype database build `2026-11-23T06:28:32Z`. This makes the
advisory sets comparable without confusing newly published advisory data with a
repository change.

### Current graph measurements

| Measurement | Observed result |
|---|---:|
| Detected modules | 1 npm module |
| Package identities | 1,091 |
| Package occurrences | 1,479 |
| Direct occurrences | 36 |
| Transitive occurrences | 1,443 |
| Dependency edges | 2,296 |
| Resolved modules | 1 |
| Partial, unsupported or failed modules | 0 |

Package identity and occurrence counts are intentionally separate. A package
identity describes a package name and exact version; an occurrence describes a
specific location and dependency context in the scanned application.

Syft observed 381 packages while Guardian's lockfile parser recovered 1,091
package identities. Guardian retains this scanner disagreement as a graph warning.
The dependency edges are derived from the npm lockfile parser, not invented from
package-name equality or by an LLM.

### Current findings

| Finding category | Count |
|---|---:|
| Confirmed advisory findings | 91 |
| CI configuration findings | 6 |
| Total findings | 97 |

Advisory findings by published severity:

| Published severity | Count |
|---|---:|
| Critical | 13 |
| High | 49 |
| Medium | 20 |
| Low | 9 |

Initial deterministic priority distribution:

| Priority | Count |
|---|---:|
| P1 | 62 |
| P2 | 20 |
| P3 | 9 |
| Needs review | 6 |

The six non-CVE findings use rule `D5-UNPINNED-ACTION`. They identify mutable
third-party GitHub Action references in actual NodeGoat workflow files. They are
configuration indicators requiring review, not claims that those actions or the
repository are malicious.

The 91 advisory records mean that the resolved package versions matched published
advisories in the captured Grype database. They do not establish runtime
reachability, exploitability, or compromise.

## 3. Completed Milestone 1 work

Milestone 1 required a real repository-to-graph demonstration. The integrated
implementation now provides the following:

1. **Safe repository intake.** Only approved GitHub HTTPS repository forms are
   accepted by the public intake path. Credentials, unexpected schemes, traversal,
   fragments, unsafe hosts and malformed inputs are rejected. Git operations use
   argument arrays, disabled hooks/submodules and bounded execution.
2. **Pinned source identity.** Public scans resolve and record a full Git commit
   SHA, source kind, scan ID, timestamps, tool versions, errors and stage states.
3. **Module discovery.** Guardian identifies npm, Python, Java, Go and Rust project
   roots using known manifest and lockfile names. Detection does not imply that a
   deep parser exists for every ecosystem; unsupported coverage stays explicit.
4. **Source SBOM.** Syft output is preserved under the run's `raw/` directory and
   published under `sbom/` for downstream scanning and export.
5. **Resolved npm graph.** The npm lockfile v2/v3 parser retains separate package
   occurrences and resolves direct and transitive relationships using installed
   lockfile locations.
6. **Canonical graph artifacts.** Each run contains `graph.json` and indexed
   `graph.sqlite`, with module roots, occurrences, dependency edges and coverage.
7. **Graph evidence.** Observed edges carry evidence IDs. Those IDs resolve through
   `evidence.jsonl` to the lockfile or SBOM source, JSON pointer, tool and hash.
8. **Bounded graph queries.** Indexed dependency path, neighborhood and reverse
   impact queries use visited sets and explicit caps. The Streamlit UI never tries
   to draw all 1,479 occurrences at once.
9. **Traceable paths.** A selected package can show its known module-to-package
   path, edge IDs and supporting evidence. Unknown relationships remain unknown.
10. **Machine-readable export.** The graph, SBOM, evidence ledger and metadata are
    preserved in the run directory and available to the UI and CLI.

## 4. Completed Day 1 work

### Advisory intelligence

Grype scans the saved SBOM rather than executing repository code. Its raw JSON,
stderr, tool version and database status are retained. Findings are mapped only to
exact resolved package versions and graph occurrences. CVE and GHSA aliases are
grouped only when the scanner supplies a verifiable alias relationship.

Failure states distinguish `BLOCKED`, `UNAVAILABLE`, `FAILED`, `PARTIAL` and
`COMPLETE`. An unavailable scanner cannot silently become “zero vulnerabilities.”
The plain public advisory function also raises a scan error when the stage did not
complete, preventing callers from treating an empty list as a successful clean scan.

### Non-CVE detection

Guardian statically parses GitHub Actions workflow YAML and records mutable
third-party action references, workflow path, job, step and the exact `uses` value.
Local actions and full SHA pins are handled as benign controls for the selected
rule. Malformed workflow files produce partial coverage rather than false safety.

The current application scan uses CI inspection to satisfy the required Day 1
non-source surface. Container image inspection was not run.

### Deterministic analysis

Findings receive transparent initial priorities from scanner facts and rule
classification. Risk scoring preserves published severity, path status, evidence
basis and unknown reachability. The integrated demonstration used
`LLM_MODE=disabled`, so no external model or API key was required.

### Reports

`guardian.reporter.create_report()` produces both `report.json` and `report.md`.
The JSON is validated against C's canonical `Report` schema before it is written.
Artifact paths are run-relative and refer only to files that exist. Missing SBOM or
incomplete stages are placed in report limitations instead of being represented as
successful blank values.

### Streamlit reviewer UI

The UI is a read-only consumer of canonical artifacts and indexed graph queries.
It currently has three views:

- **Dependency graph:** searchable package selection, depth control, a 10–150 node
  limit, direct/transitive coloring, dependency scope, source pointers, path evidence
  and SBOM download.
- **Day 1 findings:** stage and module coverage, advisory and CI finding counts,
  affected package occurrences, published severity, priority, dependency path,
  advisory links, uncertainties, recommendations and complete evidence records.
- **Time Machine:** baseline/current commit selection, package and finding deltas,
  same-advisory-snapshot warning, categorized changes, bounded changed-path graph and
  downloadable comparison JSON.

Repository-controlled strings are rendered through escaped Streamlit text, JSON,
dataframe or Graphviz string encoding. The UI does not execute repository content.

## 5. Supply Chain Time Machine

The Time Machine implementation is in `guardian/analysis/time_machine.py`, exposed
through the `guardian.cli compare` command and rendered by `ui/time_machine.py`.

It compares:

- normalized package identities;
- package occurrence locations from module and source references;
- exact version changes at the same occurrence location;
- package source type, source URL, registry host and retained integrity hashes;
- normalized dependency edges independent of scan-specific occurrence IDs;
- confirmed advisory groups attached to resolved package identities; and
- shortest bounded paths containing added packages or newly observed advisories.

The real NodeGoat comparison produced:

| Change type | Count |
|---|---:|
| Added package occurrences | 13 |
| Removed package occurrences | 0 |
| In-place version changes | 8 |
| Source or integrity record changes | 20 |
| Added dependency edges | 46 |
| Removed dependency edges | 22 |
| Highlighted changed paths | 5 |
| Newly observed advisory findings | 0 |
| Removed advisory findings | 0 |

Both commits had 91 confirmed advisory findings under the same database snapshot.
The comparison therefore does not claim that this lockfile change introduced a new
known advisory. A comparison with different or unknown advisory snapshots is
explicitly marked as unsuitable for code-change attribution.

## 6. Work completed by role

The descriptions below reflect the ownership contract and the implementation now
integrated on `main`.

### Role A — repository intake and sandbox boundary

- Implemented public GitHub URL validation and safe pinned acquisition.
- Implemented bounded static repository copying and source snapshot hashing.
- Implemented module and manifest/lockfile discovery across supported file types.
- Added controlled sample application and intake fixtures.
- Added URL, traversal, symlink, missing-lockfile, nested-module and source-unchanged
  tests.
- Kept Day 2 validation fail-closed while the complete approval/audit/isolated
  execution chain remains unavailable.

### Role B — SBOM, evidence and dependency graph

- Integrated Syft source scanning and preserved raw scanner output.
- Implemented npm lockfile occurrence and dependency-edge recovery.
- Added evidence-backed components and edges with append-only evidence handling.
- Added normalized graph JSON and SQLite persistence.
- Added bounded neighborhoods, shortest dependency paths and reverse impact.
- Added graph contract, duplicate-version, partial-failure, path-escape and oracle
  tests.

### Role C — schemas, orchestration, scoring and guard scaffolding

- Published canonical Pydantic v2 contracts and generated JSON Schemas.
- Implemented the CLI scan state machine and strict exit statuses.
- Integrated A, B and E through their public interfaces.
- Added schema and referential-integrity validation through `validate-run`.
- Added deterministic finding scoring and evidence-bound claim validation.
- Added event logging, policy loading, redaction and optional bounded model adapters.
- Added Day 2 proposal, review and approval scaffolding, which is not yet a released
  end-to-end remediation workflow.

### Role D — Streamlit UI, reports and release integration

- Implemented the bounded graph reviewer UI and evidence tables.
- Implemented Day 1 finding and coverage views.
- Implemented schema-valid JSON and Markdown reports.
- Added the Windows-compatible release checklist and UI launch script.
- Coordinated the integration branch, clean-checkout gate, `main` merge and release
  tag.

### Role E — advisory normalization, CI detector and independent QA

- Implemented the Grype adapter and advisory alias normalization.
- Implemented the GitHub Actions mutable-reference detector.
- Added frozen real advisory recordings and benign controls.
- Added independent graph oracles, contract checks and performance fixtures.
- Added negative tests for unavailable tools, invalid output, unmapped matches,
  malformed workflows and partial graph coverage.

## 7. Canonical run artifacts

Each current scan run can contain:

| Artifact | Purpose |
|---|---|
| `metadata.json` | Scan identity, source revision, status, tools, database snapshots and stage records |
| `module_index.json` | Detected modules, manifests, lockfiles, CI files and per-module coverage |
| `raw/` | Preserved scanner output, workflow evidence and error logs |
| `sbom/` | Exportable source SBOM |
| `graph.json` | Canonical modules, package occurrences, edges and coverage summary |
| `graph.sqlite` | Indexed graph query store |
| `evidence.jsonl` | Append-only observations and provenance |
| `findings.json` | Confirmed advisory and rule-based findings |
| `risk.json` | Deterministic assessments and validated claims |
| `events.jsonl` | Persisted scan workflow transitions |
| `report.json` | Canonical machine-readable review report |
| `report.md` | Readable review report |
| `comparison.json` | Time Machine delta for the two verified runs |

## 8. CLI and demonstration commands

Run these from `C:\Users\dthun\Documents\BoschHackathon`.

### Start the UI

```cmd
py -3.11 -m streamlit run ui\app.py
```

Open `http://localhost:8501`.

### Validate the current demonstration run

```cmd
py -3.11 -m guardian.cli validate-run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
```

### Print graph summary and findings

```cmd
py -3.11 -m guardian.cli graph --run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --summary
py -3.11 -m guardian.cli findings --run runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
```

### Recreate the Time Machine comparison

```cmd
py -3.11 -m guardian.cli compare --baseline runs\nodegoat-baseline\cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb --current runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --out runs\nodegoat-current\b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190\comparison.json
```

### Run the release gate

```cmd
py -3.11 scripts\release_checklist.py
```

## 9. Testing and release verification

The full repository suite passed in the normal checkout and again in a disposable
clean Git worktree at the release commit.

```text
313 passed, 8 skipped, 40 subtests passed
```

The release checklist additionally confirmed:

- canonical contract fixture files exist;
- the current NodeGoat run contains a non-empty SBOM, graph and findings;
- `validate-run` passes schema and referential-integrity checks;
- the graph contains package occurrences and dependency edges;
- confirmed advisory evidence exists;
- at least one non-CVE CI indicator exists;
- a `COMPLETE` run has populated graph and SBOM artifacts; and
- `create_report()` generates both validated report formats.

The eight skips are environment-gated tests such as optional live scanner checks
and platform-specific symlink behavior. They were reported as skipped and were not
counted as passing tests.

Streamlit AppTest loaded all three UI views without application exceptions. The
local Streamlit endpoint also returned HTTP 200.

## 10. Security properties implemented

- No shell interpolation is used for repository or scanner arguments.
- Public GitHub intake is allowlisted and commit-pinned.
- Git hooks and submodule fetching are disabled for intake.
- Repository scripts and dependency installers are not run during scanning.
- Scanner subprocesses use bounded execution and captured output.
- Repository-controlled strings do not authorize tools or state transitions.
- Evidence records retain tool, path, pointer and hash provenance.
- Evidence writing appends rather than truncating prior observations.
- Missing scanner data remains unavailable or unknown rather than becoming zero.
- Graph traversal is bounded and cycle-safe.
- Reports validate against the canonical schema before export.
- The UI is read-only for Day 1 and does not offer a decorative approval action.
- Generated run artifacts use fixed Git line-ending rules so hashes survive Windows
  and Unix checkouts.
- No credentials, host paths or known token patterns were found in the committed
  NodeGoat artifacts during the release scan.

## 11. Verified toolchain

| Tool | Verified version | Use |
|---|---:|---|
| Python | 3.11.9 | CLI, tests and Streamlit |
| Pydantic | 2.14.1 | Canonical schema validation |
| pytest | 9.1.1 | Unit, negative and integration tests |
| Streamlit | 1.67.0 | Reviewer UI |
| Git | 2.48.1.windows.1 | Pinned source acquisition |
| Syft | 1.57.2 | Source SBOM generation |
| Grype | 0.122.1 | Known-advisory scan |

Trivy and osv-scanner were unavailable. Docker CLI was present, but no container
image was built or scanned.

## 12. Known limitations

1. The current live demonstration deeply resolves npm lockfile v2/v3 data. Module
   detection covers more ecosystems, but detection is not a claim of complete deep
   dependency parsing for every ecosystem.
2. Syft and the lockfile parser report different inventory sizes. Guardian retains
   both observations and uses the supported lockfile relations for graph edges.
3. A known dependency path does not prove that vulnerable code is runtime reachable.
4. Advisory matches do not prove exploitation or malicious behavior.
5. The CI detector covers selected GitHub Actions rules. It does not prove that a
   workflow or third-party action is compromised.
6. No source-versus-container comparison exists in this release because no image
   was built or inspected.
7. Lockfile baseline detector stage `D1` remains `NOT_RUN` in the current scan
   because the scan command did not supply `--baseline-ref`. The Time Machine is a
   separate run-to-run structural comparison and does not rewrite that stage result.
8. The Time Machine compares retained normalized facts. A missing source URL or hash
   remains unknown, and different advisory snapshots disable code-change attribution.
9. The release used `LLM_MODE=disabled`. Live model-provider behavior was not tested.
10. Human review is still required for release interpretation and all remediation.

## 13. Work still outstanding

### Day 2 P0 remediation workflow

Day 2 is not complete. Some C-owned proposal, guard, event and approval scaffolding
exists, but the complete audited remediation chain has not been exercised and must
not be presented as released functionality.

The remaining critical work is:

1. Implement B's missing static fix-audit module and candidate dependency delta.
2. Complete A's `validate_approved_proposal()` implementation. It currently raises
   `ValidationBlocked` intentionally and performs no mutation or execution.
3. Verify a persisted human approval bound to the exact proposal digest.
4. Create a disposable worktree without changing the baseline source.
5. Apply only an allowlisted declarative file change.
6. Run controlled build and tests inside the required bounded isolation profile.
7. Generate a new SBOM, graph and advisory scan for the candidate.
8. Compare removed, new and remaining findings and report residual risk.
9. Test absent approval, stale or wrong hash, unsafe path, build failure, test
   failure, rescan failure, newly introduced advisory and cleanup failure.
10. Add the Day 2 before/after and validation result to the UI and final report.

No production merge, package publication or automatic deployment should be added.

### Optional improvements after Day 2 P0

- Add a second deeply supported ecosystem.
- Add a controlled source-versus-image SBOM comparison.
- Add OSV as a second advisory observation source.
- Add composite action inspection under `.github/actions/`.
- Add stable performance measurements for Time Machine comparisons at larger scales.
- Add a recorded, clearly labeled fallback video for presentation environments.

## 14. Recommended presentation flow

1. Open the **Dependency graph** view and explain the 1,091 identities, 1,479
   occurrences and 2,296 evidence-backed relations.
2. Search for a package, select it, and show its bounded neighborhood, source pointer
   and known dependency path.
3. Open **Day 1 findings** and show one confirmed advisory with its resolved version,
   advisory URL, dependency path, evidence IDs and uncertainty text.
4. Show one `D5-UNPINNED-ACTION` CI finding and explain that it is a configuration
   indicator rather than malware detection.
5. Open **Time Machine**, keep the supplied baseline and current commits selected,
   show the same advisory snapshot confirmation, and expand added packages, version
   changes, origin changes and changed paths.
6. Download `comparison.json`, `report.json`, `report.md` or the SBOM to demonstrate
   that the UI is backed by saved machine-readable evidence.
7. State the limits: static scan, no runtime reachability claim, no image scan and no
   completed Day 2 remediation yet.

## 15. Final status statement

Milestone 1 and the Day 1 P0 functionality are implemented on the audited base
release tagged `day1-integrated`. The integrated application performs a real static scan of
two pinned NodeGoat commits, produces a searchable evidence-backed dependency graph,
matches resolved packages to a captured advisory database, identifies selected CI
configuration weaknesses, exports canonical reports, and compares supply-chain
changes between commits without redrawing the entire graph.

The project is ready for the Day 1 presentation after the finalization PR receives
green CI and human review. Day 2 remediation remains an explicitly separate,
incomplete, fail-closed workstream.
