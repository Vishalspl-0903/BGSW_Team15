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
   - Select `runs/m1-demo` using the UI's Custom Run Directory option. It is a fresh CLI scan with status `PARTIAL` and passes `validate-run` in this checkout.
   - Keep the limitation visible: source graph and CI analysis completed, while advisory scanning is `BLOCKED` because Syft/SBOM is unavailable. No findings does not mean zero risk.
   - If the run is unavailable, select `tests/fixtures/contract_m1`, keep the yellow **[FIXTURE WATERMARK]** visible, and label its evidence synthetic.
   - Do not use `runs/day1-nodegoat` from this checkout: its graph and summary disagree, and its SBOM artifacts do not match the current adapters.

2. **Module Overview & Coverage Tab:**
   - Show the module root (`.`), ecosystem (`npm`), and `RESOLVED` graph coverage; explain overall scan is `PARTIAL` because advisory scanning was blocked without Syft/SBOM.
   - For the contract fixture fallback, state that it demonstrates schema and UI behavior, not a live repository scan.

3. **Component Inventory Tab:**
   - For the controlled sample, show its two package occurrences and one transitive dependency path, pointing to the original package-lock evidence.
   - For the contract fixture fallback, show the example path from `example-web` to `tiny-helper` and label every item synthetic.

4. **Dependency Graph Explorer Tab:**
   - Show the bounded graph and its `DEPENDS_ON` relationship.
   - Do not claim NodeGoat advisories or full M1 release acceptance; the controlled sample has advisory status `BLOCKED`.

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

