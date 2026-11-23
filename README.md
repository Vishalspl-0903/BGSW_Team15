# BGSW Team 15: Software Supply Chain Guardian

> **Know what you build. Trust what you ship.**
> An agentic system that analyses a software supply chain, finds dependency risks, vulnerabilities and suspicious changes, and proves every finding with evidence.

This branch (`feature/day1-dependency-graph`) contains our **Day 1 work: the "Guardian's eyes"**: discovery of every component in the sample application, its dependency graph, known vulnerabilities, and the path each one takes into the app.

**Start here:** download [`dependency-graph/output/graph.html`](dependency-graph/output/graph.html) and open it in a browser. It's an interactive graph that works offline.

---

## Milestones covered (Day 1: Build the Guardian's eyes)

| # | Day 1 milestone (organiser brief) | Status | What we delivered |
|---|---|---|---|
| 1 | **Discover components**: analyse manifests and lockfiles, identify direct and transitive dependencies, capture names and versions | ✅ Done | 1,091 packages from `package.json` + `package-lock.json`, each tagged direct/transitive, runtime/dev-only, optional |
| 2 | **Build the supply chain view**: SBOM, dependency graph, where each component originates, inspect a container image or CI/CD workflow | 🟡 Mostly done | ✅ CycloneDX 1.5 SBOM · ✅ graph with 1,977 dependency links · ✅ source URL, registry and integrity hash per package · ⏳ container image / CI workflow inspection is next |
| 3 | **Detect vulnerabilities**: match components to known vulnerabilities, capture CVE, severity and fixes, trace transitive ones back to their source | ✅ Done | 131 vulnerable packages (41 ship at runtime), 196 advisories from OSV.dev, fixed versions, and the shortest paths from the app to each one |
| 4 | **Detect suspicious changes**: at least one supply-chain anomaly | 🟡 Partly done | Real findings: a dependency downloaded from a GitHub tarball of the `master` branch (not the npm registry), an unpinned `latest` dependency, a malicious-package advisory (`fsevents@1.2.9`), install-script flags. ⏳ Comparing a baseline with a new commit ("what changed") is next |
| 5 | **Present evidence**: what was detected, which component, dependency path, supporting evidence, initial risk level | 🟡 Mostly done | Interactive graph with a details panel per package, `vulnerabilities.json`, summary tables, raw OSV responses + sha256 hashes. ⏳ Formal evidence ids and scan-status reporting are next |

**Day 1 checkpoint ("Show us what is in the application, what changed, and what appears risky"):** *what is in the application* ✅ · *what appears risky* ✅ · *what changed* ⏳.

---

## What we did

1. **Chose the sample application:** [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) (Apache-2.0), a deliberately vulnerable Node.js app with a realistic dependency tree, a committed lockfile, a Dockerfile and GitHub Actions workflows. Analysed at commit `c5cb68a7084e` (21 Jun 2023).
2. **Built the dependency graph from the lockfile only.** Nothing was installed and no package code or install script was executed. The builder links each package to its dependencies the way Node.js resolves them, then merges duplicate installs into one node per `name@version`.
3. **Classified every component:** direct vs transitive, runtime vs dev-only, optional, depth, source URL, registry, integrity hash, licence, install-script flag.
4. **Traced dependency paths:** up to 5 shortest paths from the app to every package. Runtime packages use runtime-only paths, so a path never goes through a dev tool.
5. **Matched known vulnerabilities** against [OSV.dev](https://osv.dev): one batch query for all packages, then the full advisory records (severity, CVE aliases, CVSS, smallest fixed version).
6. **Flagged supply-chain risks that aren't CVEs:** packages not downloaded from the npm registry, unpinned versions, install scripts, malicious-package advisories.
7. **Generated the outputs:** interactive HTML graph, two PNG views, machine-readable JSON, CycloneDX SBOM, summary, and evidence files (raw responses + hashes).
8. **Verified the outputs:** reviewed the PNGs; opened the HTML in a browser with no console errors; tested search, the details panel, path highlighting and the full graph including dev dependencies.

## Key results

| Metric | Value |
|---|---|
| Packages (unique `name@version`) | **1,091** |
| Dependency edges | **1,977** (0 unresolved) |
| Direct runtime / direct dev | **16 / 20** |
| Transitive | **1,055** |
| Ship at runtime / dev-only | **380 / 711** |
| Deepest dependency chain | **13** |
| Packages with known advisories (all / runtime) | **131 / 41** |
| Distinct advisories | **196** |
| Worst severity per vulnerable package | malicious 1 · critical 27 · high 65 · moderate 30 · low 8 |

**Most important findings**

| Package | How it gets into the app | Worst | Fixed in |
|---|---|---|---|
| `fsevents@1.2.9` | app → forever → forever-monitor → chokidar → fsevents (optional, macOS only) | malicious-package advisory (MAL-2023-462, CVE-2023-45311) | 1.2.11 |
| `underscore@1.9.1` | direct dependency | critical (CVE-2021-23358) | 1.13.8 |
| `bson@1.0.9` | app → mongodb → mongodb-core → bson | critical (CVE-2020-7610) | 1.1.4 |
| `marked@0.3.5` | direct dependency | high (6 advisories) | 4.0.10 |
| `body-parser@1.18.3` | direct dependency | high (3 advisories) | 1.20.9 |
| `qs@6.5.2` | app → body-parser → qs | high (CVE-2022-24999) | 6.16.0 |
| `grunt-if@0.2.0` | direct dev dependency downloaded from `github.com/.../tarball/master` | not from the npm registry, unpinned | — |

Full details: [`dependency-graph/README.md`](dependency-graph/README.md) and [`dependency-graph/output/summary.md`](dependency-graph/output/summary.md).

---

## Repository layout

```
README.md                       this file
dependency-graph/
  README.md                     detailed description, method, outputs, limits
  build_graph.py                builds the graph, queries OSV, writes JSON + SBOM
  render_graph.py               draws graph.html, the PNGs and the summary
  graph_template.html           page template for graph.html
  requirements.txt              Python dependencies
  vendor/vis-network-9.1.9.min.js   graph library (Apache-2.0 OR MIT), inlined into graph.html
  output/                       generated results (graph.html, PNGs, JSON, SBOM, evidence)
```

## Reproduce

```bash
# 1. Get the sample application at the analysed commit (do NOT npm install or start it)
git clone https://github.com/OWASP/NodeGoat sandbox/sample-app
git -C sandbox/sample-app checkout c5cb68a7084e

# 2. Build the graph
cd dependency-graph
pip install -r requirements.txt
python -I build_graph.py --repo ../sandbox/sample-app --out output
#   offline (graph only, no vulnerability lookup):  add --no-osv
```

## Safety notes

- The graph is built **without installing or running** the sample application or any of its packages.
- **NodeGoat is deliberately hackable** and listens on all network interfaces. Never run it directly on a laptop with `npm start`. Run it only in Docker, bound to localhost (`127.0.0.1:4000:4000`).
- No credentials or secrets are used or stored. The only network calls are the git clone and the public OSV.dev API (package names and versions only).

## Limits

- "Vulnerable" means the exact version has a published advisory. Whether the vulnerable code is reachable is the next step (risk prioritisation).
- Advisory data is a snapshot from OSV.dev (23 Nov 2026).
- Optional packages such as `fsevents` are installed only on supported platforms (macOS). The container image scan will confirm what actually ships.

## Next

1. Scan-status and coverage report (so "not checked" is never shown as "clean"), plus a cross-check of the graph against `npm ls`.
2. CI workflow and Dockerfile inspection, then the container image SBOM (what actually ships).
3. Change detection between a baseline and a new commit ("what changed").
4. Day 2: risk prioritisation, remediation with human approval, validation and the Guardian report.

---

*Advisory data from [OSV.dev](https://osv.dev). Sample application: OWASP NodeGoat (Apache-2.0). Graph rendering: vis-network (Apache-2.0 OR MIT).*
