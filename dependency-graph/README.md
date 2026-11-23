# Dependency graph: Day 1 "Guardian's eyes"

**Team:** BGSW Team 15 · **Event:** Bosch AI Innovation Hackathon 2026 · **Date:** 23 Nov 2026
**Deliverable:** dependency graph of the sample application, with known vulnerabilities and the path each one takes into the app.

> Open **`output/graph.html`** in any browser. It works offline.

---

## 1. What we did

| Step | What we did | Result |
|---|---|---|
| 1 | **Picked the sample app:** OWASP NodeGoat, a public, Apache-2.0, deliberately vulnerable Node.js app with a Dockerfile, a committed `package-lock.json` and real GitHub Actions workflows. | Matches the brief: public open-source app with a realistic dependency tree |
| 2 | **Cloned it with full git history** (commit `c5cb68a7084e`, 21 Jun 2023). History is kept for the later "what changed" (lockfile diff) step. | `owasp-nodejs-goat` 1.3.0, lockfile v2, 1,479 install entries |
| 3 | **Built the graph from the lockfile only.** We did **not** run `npm install`, so no package code or install script was executed. The script reads `package.json` + `package-lock.json`, links packages using Node.js module resolution, and merges duplicate installs into one node per `name@version`. | 1,091 packages, 1,977 dependency edges, 0 unresolved links |
| 4 | **Classified every package:** direct vs transitive (from `package.json`), runtime vs dev-only and optional (from lockfile flags), depth, source URL, integrity hash, licence, install-script flag. | 16 direct runtime, 20 direct dev, 1,055 transitive; 380 ship at runtime |
| 5 | **Traced dependency paths:** up to 5 shortest paths from the app to every package. Runtime packages use runtime-only paths, so a path never goes through a dev tool. | e.g. `owasp-nodejs-goat → mongodb@2.2.36 → mongodb-core@2.1.20 → bson@1.0.9` |
| 6 | **Matched known vulnerabilities** using the public **OSV.dev** database: one batch query for all 1,091 `name@version` pairs, then the full record for each of the 196 advisories. For each one we kept severity (GitHub rating, or calculated from the CVSS v3 vector), CVE ids, and the smallest fixed version above the installed one. | 131 vulnerable packages (41 at runtime), 196 distinct advisories |
| 7 | **Flagged supply-chain risks that are not CVEs:** packages not downloaded from the npm registry, unpinned versions (`latest`, URLs), install scripts, malicious-package advisories. | 1 non-registry package, 1 `latest` pin, 3 install scripts, 1 malicious-package advisory |
| 8 | **Generated the outputs:** interactive HTML graph, two PNG views, machine-readable JSON, a CycloneDX SBOM, a summary, and evidence files (raw OSV responses + sha256 hashes). | See section 3 |
| 9 | **Checked everything:** reviewed both PNGs, opened `graph.html` in a browser (no console errors), tested the details panel and path highlighting, and turned on the full graph with dev dependencies (1,091 packages; layout finishes within ~9 s). | All views work |

---

## 2. Results at a glance

| Metric | Value |
|---|---|
| Packages (unique `name@version`) | **1,091** |
| Dependency edges | **1,977** |
| Direct runtime / direct dev dependencies | **16 / 20** |
| Transitive dependencies | **1,055** |
| Ship at runtime / dev-only | **380 / 711** |
| Deepest dependency chain | **13 levels** |
| Packages installed in more than one version | 198 |
| Packages with install scripts | 3 |
| Packages not downloaded from registry.npmjs.org | 1 |
| Packages with known advisories (all / runtime) | **131 / 41** |
| Distinct advisories | **196** |
| Vulnerable packages by worst severity | malicious 1 · critical 27 · high 65 · moderate 30 · low 8 |

### Most important findings

| Package | How it gets in | Worst | Advisories | Fixed in |
|---|---|---|---|---|
| `fsevents@1.2.9` | app → forever → forever-monitor → chokidar → **fsevents** (optional, macOS only) | **malicious** | MAL-2023-462, CVE-2023-45311 | 1.2.11 |
| `underscore@1.9.1` | **direct** runtime dependency | critical | CVE-2021-23358, CVE-2026-27601 | 1.13.8 |
| `bson@1.0.9` | app → mongodb → mongodb-core → **bson** | critical | CVE-2020-7610, CVE-2019-2391 | 1.1.4 |
| `proxy-addr@2.0.4` | app → express → **proxy-addr** | critical | CVE-2026-90711 | 2.0.8 |
| `minimist@1.2.5` | app → forever → prettyjson → **minimist** | critical | CVE-2021-44906 | 1.2.6 |
| `marked@0.3.5` | **direct** runtime dependency | high | 6 advisories (e.g. CVE-2022-21681, CVE-2022-21680) | 4.0.10 |
| `body-parser@1.18.3` | **direct** runtime dependency | high | 3 advisories (e.g. CVE-2024-45590) | 1.20.9 |
| `qs@6.5.2` | app → body-parser → **qs** | high | 3 advisories (e.g. CVE-2022-24999) | 6.16.0 |
| `path-to-regexp@0.1.7` | app → express → **path-to-regexp** | high | CVE-2024-45296, CVE-2024-52798 | 0.1.13 |

**Not CVEs, but supply-chain risks:**
- `grunt-if@0.2.0` is downloaded straight from a GitHub tarball of the **master** branch, not from the npm registry. Whatever is on that branch at install time gets installed.
- `grunt-env` is declared as **`latest`**, so every fresh install can pull a different version.

The full list is in `output/summary.md` (top 20) and `output/vulnerabilities.json` (all 131).

---

## 3. Output files (`output/`)

| File | What it is |
|---|---|
| `graph.html` | **Interactive dependency graph** that needs no internet. Toggle dev dependencies, show only paths to vulnerable packages, search a package, click any node to see its version, advisories, fixed version and how it reaches the app (the path lights up in red). |
| `graph-direct.png` | The app and its 36 direct dependencies. Fill colour = the package's own worst advisory, ring = worst advisory anywhere below it, with "N below / N vulnerable" per dependency. |
| `graph-vulnerable-paths.png` | Every route from the app to its 41 vulnerable runtime packages, arranged by depth. |
| `graph.json` | Machine-readable graph: all nodes (with flags, advisories and paths) and edges. This is the input for the Day 2 risk-prioritisation agents. |
| `sbom.cdx.json` | **CycloneDX 1.5 SBOM** generated from the lockfile, with hashes, licences, download URLs and dependency relationships. |
| `vulnerabilities.json` | All 131 vulnerable packages: advisory id, CVE, severity, CVSS, summary, fixed version, dependency paths. |
| `summary.md` | Numbers + top 20 vulnerable packages + supply-chain observations. |
| `README.md` | Auto-generated description of the outputs. |
| `raw/` | **Evidence:** raw OSV responses (`osv-querybatch.json`, 196 files in `osv-vulns/`) and `evidence-hashes.json` (sha256 of every output and of the input lockfile). |

**Colour key (HTML and PNGs):** navy = application · blue = direct runtime · purple = direct dev · grey = transitive · dark purple = malicious-package advisory · dark red = critical · red = high · orange = moderate · yellow = low · dashed border = not from the npm registry.

---

## 4. How it works

```
package.json + package-lock.json (v2)
        │   no npm install, no scripts executed
        ▼
build_graph.py ── resolve each dependency the way Node.js does (nested node_modules first, then parents)
        │       ── merge duplicates into one node per name@version
        │       ── breadth-first search from the app → depth + shortest paths (runtime-only for runtime packages)
        ▼
OSV.dev API ──── one batch query for all packages, then the full advisory records (saved as evidence)
        ▼
render_graph.py ─ graph.html (vis-network, inlined) · 2 PNGs (matplotlib) · summary.md · README.md
        ▼
graph.json · sbom.cdx.json · vulnerabilities.json · raw/ evidence
```

**Tools used:** Python 3.11, matplotlib (PNGs), vis-network 9.1.9 (interactive graph, bundled in `vendor/`), OSV.dev public API (advisories), git.

---

## 5. How to run it again

From the repository root:

```bash
git clone https://github.com/OWASP/NodeGoat sandbox/sample-app
git -C sandbox/sample-app checkout c5cb68a7084e

cd dependency-graph
pip install -r requirements.txt
python -I build_graph.py --repo ../sandbox/sample-app --out output
python -I build_graph.py --repo ../sandbox/sample-app --out output --no-osv   # offline, graph only
```

Advisories already downloaded in `output/raw/osv-vulns/` are reused, so re-runs are fast. `sandbox/` is git-ignored.

---

## 6. Limits (stated honestly)

- **Known advisories, not proven exploitability.** "Vulnerable" means this exact version has a published advisory. Whether the vulnerable code is actually reachable from NodeGoat is the Day 2 prioritisation step.
- **Advisory data is a snapshot** from OSV.dev taken on 23 Nov 2026. Some 2026 CVE ids come directly from OSV's live data and were not checked individually.
- **Optional packages** such as `fsevents` are installed only on supported platforms (macOS). They are labelled "optional". NodeGoat's Dockerfile builds a Linux image with `npm install --production`, so `fsevents` probably does not ship in the container. The container image SBOM will confirm what actually ships.
- **Dev-only packages are counted** in the totals (711 of 1,091) but hidden by default in the interactive view, because they don't ship with the app.
- **If OSV is skipped (`--no-osv`)**, packages currently show "no known advisory". Showing "not checked" instead is on the next-steps list.
- **No container or CI scan yet.** Docker image and GitHub Actions inspection come next.

---

## 7. Next steps

1. Scan-status and coverage report (so "not checked" is never shown as "clean") and a cross-check of the graph against `npm ls --all --package-lock-only`.
2. Inspect the CI workflows (`.github/workflows/e2e-test.yml`, `lint.yml`) and the Dockerfile; build the image and generate its SBOM.
3. Compare a baseline commit with a new one ("what changed") and add the supply-chain change detectors.
4. Feed `graph.json` into the Day 2 risk-prioritisation and remediation agents.
