# Dependency graph: owasp-nodejs-goat 1.3.0

- **Application:** https://github.com/OWASP/NodeGoat @ `c5cb68a7084e` (commit date 2023-06-21)
- **Input:** `package.json` + `package-lock.json` (lockfile v2, sha256 `d6ca7e31c3a099d8...`)
- **Generated:** 2026-11-23T09:24:17+00:00 by guardian build_graph.py 0.1.0 (python 3.11.9)
- **Advisory data:** OSV.dev, queried 2026-11-23T09:24:21+00:00

Nothing was installed and no package scripts were run: the graph is built only from the lockfile.
Each node is one `name@version`; edges follow Node.js module resolution over the lockfile's install paths
(1977 edges, 0 unresolved).

## Files

| File | What it is |
|---|---|
| `graph.html` | **Interactive graph** (open in any browser, works offline). Toggle dev dependencies, show only paths to vulnerable packages, search, click a package to see its advisories and how it reaches the app. |
| `graph-direct.png` | The application and its 36 direct dependencies. Fill = the package itself, ring = worst advisory anywhere below it. |
| `graph-vulnerable-paths.png` | Runtime paths from the application to every vulnerable runtime package, by depth. |
| `graph.json` | Machine-readable graph: nodes (version, direct/transitive, runtime/dev, depth, source URL, integrity, licence, install-script flag, advisories, paths) and edges. |
| `sbom.cdx.json` | CycloneDX 1.5 SBOM generated from the lockfile, including the dependency relationships. |
| `vulnerabilities.json` | Every vulnerable package with its advisories (id, CVE, severity, CVSS, fixed version) and dependency paths. |
| `raw/` | Evidence: raw OSV responses and sha256 hashes of every output and of the input lockfile. |

## Summary

| Metric | Value |
|---|---|
| Packages (unique name@version) | 1091 |
| Dependency edges | 1977 |
| Direct runtime / direct dev | 16 / 20 |
| Transitive | 1055 |
| Runtime packages / dev-only packages | 380 / 711 |
| Deepest dependency chain | 13 |
| Packages present in more than one version | 198 |
| Packages with install scripts | 3 |
| Packages not resolved from registry.npmjs.org | 1 |
| Packages with known advisories (all / runtime) | 131 / 41 |
| Distinct advisories | 196 |
| Vulnerable packages by worst severity | malicious 1, critical 27, high 65, moderate 30, low 8 |

### Top vulnerable packages (runtime first)

| Package | Scope | Worst | Advisories | Fixed in | Dependency path |
|---|---|---|---|---|---|
| `fsevents@1.2.9` | runtime (optional) | malicious | 2: MAL-2023-462, CVE-2023-45311 | 1.2.11 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9 |
| `tar@4.4.8` | runtime (optional) | critical | 18: CVE-2026-59873, CVE-2026-23950, CVE-2026-24842 ... | 7.5.21 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9 → node-pre-gyp@0.12.0 → tar@4.4.8 |
| `bson@1.0.9` | runtime | critical | 2: CVE-2020-7610, CVE-2019-2391 | 1.1.4 | owasp-nodejs-goat → mongodb@2.2.36 → mongodb-core@2.1.20 → bson@1.0.9 |
| `minimist@0.0.10` | runtime | critical | 2: CVE-2021-44906, CVE-2020-7598 | 0.2.4 | owasp-nodejs-goat → forever@2.0.0 → optimist@0.6.1 → minimist@0.0.10 |
| `minimist@0.0.8` | runtime | critical | 2: CVE-2021-44906, CVE-2020-7598 | 0.2.4 | owasp-nodejs-goat → forever@2.0.0 → mkdirp@0.5.1 → minimist@0.0.8 |
| `minimist@1.2.0` | runtime | critical | 2: CVE-2021-44906, CVE-2020-7598 | 1.2.6 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → fsevents@1.2.9 → node-pre-gyp@0.12.0 → rc@1.2.8 → minimist@1.2.0 |
| `set-value@0.4.3` | runtime | critical | 2: CVE-2019-10747, CVE-2021-23440 | 2.0.1 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → union-value@1.0.0 → set-value@0.4.3 |
| `set-value@2.0.0` | runtime | critical | 2: CVE-2019-10747, CVE-2021-23440 | 2.0.1 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → cache-base@1.0.1 → set-value@2.0.0 |
| `underscore@1.9.1` | direct runtime | critical | 2: CVE-2021-23358, CVE-2026-27601 | 1.13.8 | owasp-nodejs-goat → underscore@1.9.1 |
| `minimist@1.2.5` | runtime | critical | 1: CVE-2021-44906 | 1.2.6 | owasp-nodejs-goat → forever@2.0.0 → prettyjson@1.2.1 → minimist@1.2.5 |
| `mixin-deep@1.3.1` | runtime | critical | 1: CVE-2019-10746 | 1.3.2 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → base@0.11.2 → mixin-deep@1.3.1 |
| `proxy-addr@2.0.4` | runtime | critical | 1: CVE-2026-90711 | 2.0.8 | owasp-nodejs-goat → express@4.16.4 → proxy-addr@2.0.4 |
| `brace-expansion@1.1.11` | runtime | high | 8: CVE-2026-102276, CVE-2026-14257, CVE-2026-102278 ... | 1.1.21 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → minimatch@3.0.4 → brace-expansion@1.1.11 |
| `marked@0.3.5` | direct runtime | high | 6: CVE-2022-21681, CVE-2022-21680, CVE-2017-16114 ... | 4.0.10 | owasp-nodejs-goat → marked@0.3.5 |
| `minimatch@3.0.4` | runtime | high | 4: CVE-2026-27904, CVE-2026-27903, CVE-2022-3517 ... | 3.1.4 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → minimatch@3.0.4 |
| `body-parser@1.18.3` | direct runtime | high | 3: CVE-2026-111181, CVE-2024-45590, CVE-2026-12590 | 1.20.9 | owasp-nodejs-goat → body-parser@1.18.3 |
| `decode-uri-component@0.2.0` | runtime | high | 3: CVE-2022-38900, CVE-2026-118664, CVE-2026-45822 | 0.5.1 | owasp-nodejs-goat → forever@2.0.0 → forever-monitor@2.0.0 → chokidar@2.1.8 → braces@2.3.2 → snapdragon@0.8.2 → source-map-resolve@0.5.2 → decode-uri-component@0.2.0 |
| `path-to-regexp@0.1.7` | runtime | high | 2: CVE-2024-45296, CVE-2024-52798 | 0.1.13 | owasp-nodejs-goat → express@4.16.4 → path-to-regexp@0.1.7 |
| `qs@6.5.2` | runtime | high | 3: CVE-2022-24999, CVE-2026-82417, CVE-2025-15284 | 6.16.0 | owasp-nodejs-goat → body-parser@1.18.3 → qs@6.5.2 |
| `debug@2.2.0` | runtime | high | 2: CVE-2017-20165, CVE-2017-16137 | 2.6.9 | owasp-nodejs-goat → helmet@2.3.0 → connect@3.4.1 → debug@2.2.0 |

### Supply-chain observations (non-CVE)

- `grunt-if@0.2.0` is not resolved from the npm registry: https://github.com/binarymist/grunt-if/tarball/master
- `grunt-env` is declared as `latest` in `devDependencies` (not pinned to a version range)
- `grunt-if` is declared as `https://github.com/binarymist/grunt-if/tarball/master` in `devDependencies` (not pinned to a version range)


## How to read it

- **Direct** = declared in `package.json`. **Transitive** = pulled in by another package. **Runtime** = shipped with the app; **dev-only** = only used for building and testing.
- **Optional** packages (e.g. `fsevents`) are only installed on platforms that support them (macOS for `fsevents`).
- Severity is the worst known advisory for that exact version. It does not yet say whether the vulnerable code is reachable; that is the next step (risk prioritisation).

## Regenerate

```
python -I build_graph.py --repo ../sandbox/sample-app --out output
python -I build_graph.py --repo ../sandbox/sample-app --out output --no-osv   # offline, graph only
```
Requires Python 3.10+ and `matplotlib` (for the PNGs). `vendor/vis-network-9.1.9.min.js` is inlined into `graph.html`, so the page needs no internet.
