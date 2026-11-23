# Bosch Software Supply Chain Guardian — Demo Script

This script provides step-by-step instructions for rehearsed, truthful evaluator demonstrations. All demonstrations run directly from `main` or the integrated branch with zero fabricated data.

---

## 1. Quick Startup Command
To launch the Guardian Reviewer UI:

**Windows PowerShell / Command Prompt:**
```cmd
.\scripts\run_ui.bat
```
*Or directly:*
```bash
python -m streamlit run ui/app.py
```

The application opens at `http://localhost:8501`.

---

## 2. Milestone 1 Demo (2–3 Minutes)
**Theme:** *Evidence-first dependency graph discovery & honest coverage limits.*

1. **Select Run / Fixture:**
   - In the sidebar, select `runs/day1-nodegoat` (or `tests/fixtures/contract_m1`).
   - Notice the scan metadata: commit SHA `c5cb68a7084e`, source kind `GIT_PUBLIC`, and intake status `COMPLETE`.
   - Point out that if a fixture is loaded, the yellow **[FIXTURE WATERMARK]** appears prominently; for real runs, it is hidden.

2. **Module Overview & Coverage Tab:**
   - Show the detected module root (`.`), ecosystem (`npm`), and coverage status (`RESOLVED`).
   - Explain: *"Guardian explicitly records what is resolved versus partial. Unknowns and scanner failures are never masked as safe."*

3. **Component Inventory Tab:**
   - Note the package count: **1,091 components**, **1,977 dependency edges**.
   - Type `express` in the search filter to display direct and transitive components.
   - Select a transitive component (e.g. `qs@6.7.0`):
     - Show the **Traceable Dependency Path**: `mod-root ➔ occ-express-4.17.1 ➔ occ-qs-6.7.0`.
     - Point out the provenance: exact source lockfile line, package URL (`purl`), and artifact SHA-256 integrity hash.

4. **Dependency Graph Explorer Tab:**
   - Explain scalability: *"We never dump 1,000+ nodes into a browser force-directed layout."*
   - Select the center node, adjust the neighborhood depth to `1` or `2`, and show the bounded neighborhood.
   - Show the adjacency connection table with verified `DEPENDS_ON` relationships.

---

## 3. Day 1 Demo (3–4 Minutes)
**Theme:** *Real CVE matching, non-CVE indicators, and verifiable reporting.*

1. **Findings & Evidence Tab:**
   - Click on the **🛡️ Verified Advisories** sub-tab:
     - Show real OSV/GHSA advisories attached to exact package occurrences (e.g. Prototype pollution in `qs@6.7.0`).
     - Point out the evidence card: advisory URL, affected version, priority (`P1`), and runtime execution indicator.
   - Click on the **⚠️ Suspicious Indicators** sub-tab:
     - Show non-CVE findings: unpinned `latest` dependency (`grunt-env`) and non-registry tarball URL dependency.
     - Explain: *"We flag indicators of risk with observed facts, without claiming proven malware."*
   - Click on the **🔍 Coverage Gaps** sub-tab:
     - Point out that container image scanning was not executed for this run; Guardian clearly states this as a coverage limitation rather than claiming the image is safe.

2. **Reports & Export Tab:**
   - Click **Generate Fresh Report Artifacts**.
   - Show the generated `report.json` and `report.md`.
   - Click **Download report.json** and **Download report.md**.
   - Show the rendered Markdown preview, emphasizing the *Artifact Integrity & Provenance* section.

---

## 4. Day 2 Demo (4–5 Minutes)
**Theme:** *Fix audit, Critic/Guard review, authentic human authorization, and validation.*

1. **Fix Audit & Approval Tab:**
   - Display Candidate Proposal `prop-upgrade-express`:
     - Strategy: `DIRECT_UPGRADE` to `4.18.2`.
     - Show the before/after file patch and rationale.
   - Show Critic & Guard verdicts:
     - Static audit verified package integrity sha512.
     - Critic confirmed fix resolves target CVE without introducing new transitive CVEs.
   - Show the **Human Authorization Gate**:
     - Explain: *"Approval buttons in Guardian are authentic. In this handoff checkpoint, without an active state backend daemon, the UI explicitly indicates read-only fail-closed mode (§14 D.3 / §21 G15). No decorative mock transitions are permitted."*
   - Show the **Independent Worktree Validation Results**:
     - Status: `PASS`, Build & Tests: `PASSED`, Rescan: `COMPLETED`.
     - Findings delta: `find-cve-001` removed; residual findings transparently retained.

