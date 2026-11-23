# Bosch Software Supply Chain Guardian 🛡️

> **Evidence-first software supply chain decision system.**  
> *"Discover what the software depends on, prove what we know and don't know, challenge the proposed fix, and validate safer delivery."*

---

## 1. Quick Start (One-Command UI Launch)

### Prerequisites
- Python 3.11 or 3.12 installed.

### Launch Guardian Reviewer UI

**Windows:**
```cmd
.\scripts\run_ui.bat
```

**Linux / macOS:**
```bash
python -m streamlit run ui/app.py
```

The reviewer interface will open in your browser at `http://localhost:8501`.

---

## 2. Running Automated Tests & Release Verification

Run the full automated test suite:
```bash
python -m pytest -q
```

Run the Day 1 Release Train Verification Checklist (§16 / §21):
```bash
python scripts/release_checklist.py
```

---

## 3. Key Capabilities & Architectural Scope

Guardian is built on the premise that **a guardian cannot protect what it has not reliably discovered**.

### 📦 M1: Scalable Supply Chain Graph & Traceable Provenance
- **Safe Static Intake:** Parses lockfiles and manifests without executing untrusted install scripts.
- **Transitive Dependency Resolution:** Resolves deep transitive package occurrences (e.g. `express ➔ qs`) without requiring explicit source imports.
- **Traceable Paths:** Computes deterministic shortest paths from the project root module to any vulnerable transitive dependency.
- **Scalable Bounded Rendering:** Avoids browser-crashing force-layouts on large graphs by enforcing bounded neighborhood queries (capped at 150 nodes) and expandable adjacency lists. Verified on synthetic 10,000-component fixtures.
- **Fixture Watermark:** Displays an explicit `[FIXTURE WATERMARK]` whenever mock or test data is shown, ensuring synthetic data is never confused with live scans.

### 🛡️ Day 1: Categorized Security Findings & Provenance
- **Confirmed Advisories:** Grype matches resolved package occurrences to CVE/GHSA records using a captured database snapshot, with published severity and fix information when available.
- **CI Policy Indicators:** Flags mutable third-party GitHub Action references and records the exact workflow location. These are review indicators, not proof of compromise.
- **Coverage Gap Visibility:** Explicitly records scanner limitations (e.g., container scan not executed) as coverage gaps rather than claiming false safety.
- **Verifiable Reports:** Generates machine-readable `report.json` and human-readable `report.md` via `guardian.reporter.create_report()`.
- **Supply Chain Time Machine:** Compares two canonical scan runs for package, version, source, edge and advisory changes. Vulnerability changes are attributed to code only when both runs used the same advisory snapshot.

Static scanning and comparison use the CLI; Streamlit reads the resulting artifacts:

```powershell
py -3.11 -m guardian.cli validate-run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli report --run runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190
py -3.11 -m guardian.cli compare --baseline runs/nodegoat-baseline/cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb --current runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190 --out runs/nodegoat-current/b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190/comparison.json
py -3.11 -m streamlit run ui/app.py
```

### 🔧 Day 2: Scaffolded, Not Released
- Proposal, Critic, Guard, event and hash-bound approval contracts exist as scaffolding.
- A's validator intentionally fails closed, and B's static fix-audit module is not implemented.
- No approved patch/build/test/rescan case has been completed. Do not present Day 2 remediation as working functionality.

---

## 4. Repository Structure & Ownership

```text
├── .github/workflows/ci.yml       # Automated project CI pipeline
├── guardian/
│   ├── intake.py                  # [A] Safe static intake & URL normalizer
│   ├── module_index.py            # [A] Multi-module repository indexer
│   ├── reporter.py                # [D] Report generation & graph traversal queries
│   └── validator.py               # [A] Day 2 fail-closed validation placeholder
├── ui/
│   ├── app.py                     # [D] Streamlit reviewer interface
│   ├── day1.py                    # [D] Findings, coverage and evidence view
│   ├── time_machine.py            # [D] Two-commit comparison view
│   └── requirements.txt           # Runtime/CI dependencies
├── docs/
│   ├── demo-script.md             # [D] Step-by-step 2–5 minute presentation guide
│   ├── day1_release.md            # [D] Normative Day 1 sign-off record (§16.5)
│   └── responsible-ai.md          # [D] System safety & Responsible AI principles
├── scripts/
│   ├── run_ui.bat                 # [D] Windows one-command startup script
│   └── release_checklist.py       # [D] Automated release train verification (§16/21)
├── tests/
│   ├── a_intake/                  # [A] Intake & module index unit tests
│   ├── a_validator/               # [A] Proposal validation unit tests
│   ├── d_report/                  # [D] Report generator & snapshot tests
│   └── d_ui/                      # [D] UI smoke, bounded scale & XSS tests
└── runs/
    ├── nodegoat-baseline/         # Earlier pinned NodeGoat comparison run
    └── nodegoat-current/          # Current run: 1,091 identities, 91 advisory findings
```

---

## 5. Non-Negotiable Honesty
- Unknown dependencies are never shown as safe.
- Missing evidence records are explicitly labeled `NOT_AVAILABLE`.
- Vulnerability detection is performed solely by scanning engines; the UI never fabricates security claims or findings.

