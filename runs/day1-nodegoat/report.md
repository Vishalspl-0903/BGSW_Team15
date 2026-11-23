# Guardian Supply Chain Security Report

> **Scan ID:** `scan-nodegoat-day1` | **Status:** `COMPLETE` | **Source:** `GIT_PUBLIC`
> **Repository:** `https://github.com/OWASP/NodeGoat` | **Commit:** `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`

---

## 1. Supply Chain Inventory & Coverage Summary

| Metric | Count | Note |
|---|---|---|
| Total Modules | 1 | Monorepo/sub-projects detected |
| Resolved Modules | 1 | Full lockfile resolution |
| Partial Modules | 0 | Unresolved dependencies present |
| Total Components | 0 | Unique package occurrences |
| Dependency Edges | 0 | Direct & transitive graph relationships |

## 2. Findings Summary

- **Total Security Findings:** 133
- **Priority Breakdown:** P0: 27, P1: 65, P2: 41, P3: 0
- **Classifications:**
  - `CONFIRMED_ADVISORY`: 131
  - `SUSPICIOUS_INDICATOR`: 2

## 3. Detailed Security Findings

| Priority | Finding ID | Classification | Title | Advisory / Rule | Stage | Evidence |
|---|---|---|---|---|---|---|
| **P0** | `finding-nodegoat-002` | `CONFIRMED_ADVISORY` | Deserialization of Untrusted Data in bson | GHSA-v8w9-2789-6hhr, GHSA-4jwp-vfvf-657p | `RUNTIME` | `ev-nodegoat-bson@1.0.9` |
| **P0** | `finding-nodegoat-003` | `CONFIRMED_ADVISORY` | Prototype Pollution in minimist | GHSA-xvch-5gv4-984h, GHSA-vh95-rmgr-6w4m | `RUNTIME` | `ev-nodegoat-minimist@0.0.10` |
| **P0** | `finding-nodegoat-004` | `CONFIRMED_ADVISORY` | Prototype Pollution in minimist | GHSA-xvch-5gv4-984h, GHSA-vh95-rmgr-6w4m | `RUNTIME` | `ev-nodegoat-minimist@0.0.8` |
| **P0** | `finding-nodegoat-005` | `CONFIRMED_ADVISORY` | Prototype Pollution in minimist | GHSA-xvch-5gv4-984h, GHSA-vh95-rmgr-6w4m | `RUNTIME` | `ev-nodegoat-minimist@1.2.0` |
| **P0** | `finding-nodegoat-006` | `CONFIRMED_ADVISORY` | Prototype Pollution in minimist | GHSA-xvch-5gv4-984h | `RUNTIME` | `ev-nodegoat-minimist@1.2.5` |
| **P0** | `finding-nodegoat-007` | `CONFIRMED_ADVISORY` | Prototype Pollution in mixin-deep | GHSA-fhjf-83wg-r2j9 | `RUNTIME` | `ev-nodegoat-mixin-deep@1.3.1` |
| **P0** | `finding-nodegoat-008` | `CONFIRMED_ADVISORY` | proxy-addr vulnerable to IP spoofing via IPv4-mapped IPv6 tr | GHSA-jqcg-44mw-7w3h | `RUNTIME` | `ev-nodegoat-proxy-addr@2.0.4` |
| **P0** | `finding-nodegoat-009` | `CONFIRMED_ADVISORY` | Prototype Pollution in set-value | GHSA-4g88-fppr-53pp, GHSA-4jqc-8m5r-9rpr | `RUNTIME` | `ev-nodegoat-set-value@0.4.3` |
| **P0** | `finding-nodegoat-010` | `CONFIRMED_ADVISORY` | Prototype Pollution in set-value | GHSA-4g88-fppr-53pp, GHSA-4jqc-8m5r-9rpr | `RUNTIME` | `ev-nodegoat-set-value@2.0.0` |
| **P0** | `finding-nodegoat-011` | `CONFIRMED_ADVISORY` | node-tar: Decompression/parse DoS via unlimited input | GHSA-23hp-3jrh-7fpw, GHSA-r6q2-hw4h-h46w, GHSA-34x7-hfp2-rc4v, GHSA-3jfq-g458-7qm9, GHSA-5955-9wpr-37jh, GHSA-9r2w-394v-53qc, GHSA-qq89-hq3f-393p, GHSA-r628-mhmh-qjhw, GHSA-8x88-c5mf-7j5w, GHSA-r292-9mhp-454m, GHSA-83g3-92jg-28cx, GHSA-8qq5-rm4j-mr97, GHSA-9ppj-qmqm-q256, GHSA-qffp-2rhf-9h96, GHSA-f5x3-32g6-xq36, GHSA-gvwx-54wh-qm9j, GHSA-w8wr-v893-vjvp, GHSA-vmf3-w455-68vh | `RUNTIME` | `ev-nodegoat-tar@4.4.8` |
| **P0** | `finding-nodegoat-012` | `CONFIRMED_ADVISORY` | Arbitrary Code Execution in underscore | GHSA-cf4h-3jhx-xvhq, GHSA-qpx9-hpmf-5gmw | `RUNTIME` | `ev-nodegoat-underscore@1.9.1` |
| **P0** | `finding-nodegoat-013` | `CONFIRMED_ADVISORY` | Babel vulnerable to arbitrary code execution when compiling  | GHSA-67hx-6x53-jw92 | `BUILD` | `ev-nodegoat-babel-traverse@6.11.4` |
| **P0** | `finding-nodegoat-014` | `CONFIRMED_ADVISORY` | form-data uses unsafe random function in form-data for choos | GHSA-fjxv-7rqg-78g4, GHSA-hmw2-7cc7-3qxx | `BUILD` | `ev-nodegoat-form-data@0.1.4` |
| **P0** | `finding-nodegoat-015` | `CONFIRMED_ADVISORY` | form-data uses unsafe random function in form-data for choos | GHSA-fjxv-7rqg-78g4, GHSA-hmw2-7cc7-3qxx | `BUILD` | `ev-nodegoat-form-data@1.0.1` |
| **P0** | `finding-nodegoat-016` | `CONFIRMED_ADVISORY` | form-data uses unsafe random function in form-data for choos | GHSA-fjxv-7rqg-78g4, GHSA-hmw2-7cc7-3qxx | `BUILD` | `ev-nodegoat-form-data@2.0.0` |
| **P0** | `finding-nodegoat-017` | `CONFIRMED_ADVISORY` | form-data uses unsafe random function in form-data for choos | GHSA-fjxv-7rqg-78g4, GHSA-hmw2-7cc7-3qxx | `BUILD` | `ev-nodegoat-form-data@2.1.4` |
| **P0** | `finding-nodegoat-018` | `CONFIRMED_ADVISORY` | form-data uses unsafe random function in form-data for choos | GHSA-fjxv-7rqg-78g4, GHSA-hmw2-7cc7-3qxx | `BUILD` | `ev-nodegoat-form-data@2.3.3` |
| **P0** | `finding-nodegoat-019` | `CONFIRMED_ADVISORY` | Prototype pollution in getobject | GHSA-957j-59c2-j692 | `BUILD` | `ev-nodegoat-getobject@0.1.0` |
| **P0** | `finding-nodegoat-020` | `CONFIRMED_ADVISORY` | Growl before 1.10.0 vulnerable to Command Injection | GHSA-qh2h-chj9-jffq | `BUILD` | `ev-nodegoat-growl@1.9.2` |
| **P0** | `finding-nodegoat-021` | `CONFIRMED_ADVISORY` | Handlebars.js has JavaScript Injection via AST Type Confusio | GHSA-2w6w-674q-4c4q, GHSA-765h-qjxv-5f44, GHSA-8r5x-fm3f-whwj, GHSA-f2jv-r9rf-7988, GHSA-w457-6q6x-cgp9, GHSA-p8wg-vrv2-v86f, GHSA-xjpj-3mr7-gcpf, GHSA-3cqr-58rm-57f8, GHSA-3mfm-83xf-c92r, GHSA-xhpv-hc6g-r9c6, GHSA-62gr-4qp9-h98f, GHSA-9cx6-37pm-9jff, GHSA-2cf5-4w76-r9qv, GHSA-q42p-pg8m-cqh6, GHSA-g9r4-xpmj-mj65, GHSA-q2c6-c6pm-g3gh, GHSA-2qvq-rjwj-gvw9, GHSA-xw65-4hp5-5hc7, GHSA-f52g-6jhx-586p, GHSA-442j-39wm-28r2 | `BUILD` | `ev-nodegoat-handlebars@4.0.5` |
| **P0** | `finding-nodegoat-022` | `CONFIRMED_ADVISORY` | json-schema is vulnerable to Prototype Pollution | GHSA-896r-f27r-55mw | `BUILD` | `ev-nodegoat-json-schema@0.2.3` |
| **P0** | `finding-nodegoat-023` | `CONFIRMED_ADVISORY` | Prototype Pollution in lodash | GHSA-jf85-cpcp-j695, GHSA-35jh-r3h4-6jhm, GHSA-4xc9-xhrj-v574, GHSA-fvqr-27wr-82fm | `BUILD` | `ev-nodegoat-lodash@2.4.2` |
| **P0** | `finding-nodegoat-024` | `CONFIRMED_ADVISORY` | Prototype Pollution in lodash | GHSA-jf85-cpcp-j695, GHSA-r5fr-rjxr-66jc, GHSA-p6mc-m468-83gw, GHSA-35jh-r3h4-6jhm, GHSA-4xc9-xhrj-v574, GHSA-fvqr-27wr-82fm, GHSA-x5rq-j2xg-h7qm, GHSA-xxjr-mmjv-4gpg, GHSA-29mw-wpgm-hmr9 | `BUILD` | `ev-nodegoat-lodash@4.13.1` |
| **P0** | `finding-nodegoat-025` | `CONFIRMED_ADVISORY` | Prototype Pollution in lodash | GHSA-jf85-cpcp-j695, GHSA-r5fr-rjxr-66jc, GHSA-p6mc-m468-83gw, GHSA-35jh-r3h4-6jhm, GHSA-xxjr-mmjv-4gpg, GHSA-29mw-wpgm-hmr9 | `BUILD` | `ev-nodegoat-lodash@4.17.11` |
| **P0** | `finding-nodegoat-026` | `CONFIRMED_ADVISORY` | node-tar: Decompression/parse DoS via unlimited input | GHSA-23hp-3jrh-7fpw, GHSA-r6q2-hw4h-h46w, GHSA-34x7-hfp2-rc4v, GHSA-3jfq-g458-7qm9, GHSA-5955-9wpr-37jh, GHSA-8x88-c5mf-7j5w, GHSA-j44m-qm6p-hp7m, GHSA-r292-9mhp-454m, GHSA-83g3-92jg-28cx, GHSA-8qq5-rm4j-mr97, GHSA-9ppj-qmqm-q256, GHSA-qffp-2rhf-9h96, GHSA-f5x3-32g6-xq36, GHSA-gvwx-54wh-qm9j, GHSA-w8wr-v893-vjvp, GHSA-vmf3-w455-68vh | `BUILD` | `ev-nodegoat-tar@2.2.1` |
| **P0** | `finding-nodegoat-027` | `CONFIRMED_ADVISORY` | Arbitrary Code Execution in underscore | GHSA-cf4h-3jhx-xvhq, GHSA-qpx9-hpmf-5gmw | `BUILD` | `ev-nodegoat-underscore@1.8.3` |
| **P0** | `finding-nodegoat-028` | `CONFIRMED_ADVISORY` | websocket-driver: Message corruption via abuse of protocol l | GHSA-xv26-6w52-cph6, GHSA-mp7j-qc5w-4988 | `BUILD` | `ev-nodegoat-websocket-driver@0.7.0` |
| **P1** | `finding-nodegoat-029` | `CONFIRMED_ADVISORY` | body-parser vulnerable to Denial of Service via trailing byt | GHSA-27r3-jxmh-p828, GHSA-qwcr-r2fm-qrc7, GHSA-v422-hmwv-36x6 | `RUNTIME` | `ev-nodegoat-body-parser@1.18.3` |
| **P1** | `finding-nodegoat-030` | `CONFIRMED_ADVISORY` | brace-expansion: DoS via uncontrolled recursion in parseComm | GHSA-6j4f-fj2g-mc7p, GHSA-mh99-v99m-4gvg, GHSA-qhr7-859c-m2p7, GHSA-rgw5-rvv9-x895, GHSA-3jxr-9vmj-r5cp, GHSA-f886-m6hf-6m8v, GHSA-q2hr-2g5m-vwhr, GHSA-v6h2-p8h4-qcjw | `RUNTIME` | `ev-nodegoat-brace-expansion@1.1.11` |
| **P1** | `finding-nodegoat-031` | `CONFIRMED_ADVISORY` | Uncontrolled resource consumption in braces | GHSA-grv7-fg5c-xmjg | `RUNTIME` | `ev-nodegoat-braces@2.3.2` |
| **P1** | `finding-nodegoat-032` | `CONFIRMED_ADVISORY` | debug Inefficient Regular Expression Complexity vulnerabilit | GHSA-9vvw-cc9w-f27h, GHSA-gxpj-cx7g-858c | `RUNTIME` | `ev-nodegoat-debug@2.2.0` |
| **P1** | `finding-nodegoat-033` | `CONFIRMED_ADVISORY` | decode-uri-component vulnerable to Denial of Service (DoS) | GHSA-w573-4hg7-7wgq, GHSA-qr28-fpjm-wq7f, GHSA-vcc3-ghjq-m6fr | `RUNTIME` | `ev-nodegoat-decode-uri-component@0.2.0` |
| **P1** | `finding-nodegoat-034` | `CONFIRMED_ADVISORY` | inflect vulnerable to Inefficient Regular Expression Complex | GHSA-x55w-vjjp-222r | `RUNTIME` | `ev-nodegoat-i@0.3.6` |
| **P1** | `finding-nodegoat-035` | `CONFIRMED_ADVISORY` | ini before 1.3.6 vulnerable to Prototype Pollution via ini.p | GHSA-qqgx-2p2h-9c37 | `RUNTIME` | `ev-nodegoat-ini@1.3.5` |
| **P1** | `finding-nodegoat-036` | `CONFIRMED_ADVISORY` | Validation Bypass in kind-of | GHSA-6c8f-qphg-qjgp | `RUNTIME` | `ev-nodegoat-kind-of@6.0.2` |
| **P1** | `finding-nodegoat-037` | `CONFIRMED_ADVISORY` | Inefficient Regular Expression Complexity in marked | GHSA-5v2h-r2cx-5xgj, GHSA-rrrm-qjm4-v8hf, GHSA-x5pg-88wf-qq4p, GHSA-7px7-7xjx-hxm8, GHSA-vfvf-mqq8-rwqc, GHSA-p9wx-2529-fp83 | `RUNTIME` | `ev-nodegoat-marked@0.3.5` |
| **P1** | `finding-nodegoat-038` | `CONFIRMED_ADVISORY` | minimatch ReDoS: nested *() extglobs generate catastrophical | GHSA-23c5-xmqv-rm74, GHSA-7r86-cg39-jmmj, GHSA-f8q6-p94x-37v3, GHSA-3ppc-4f35-3m26 | `RUNTIME` | `ev-nodegoat-minimatch@3.0.4` |
| **P1** | `finding-nodegoat-039` | `CONFIRMED_ADVISORY` | Denial of Service in mongodb | GHSA-mh5c-679w-hh4r | `RUNTIME` | `ev-nodegoat-mongodb@2.2.36` |
| **P1** | `finding-nodegoat-040` | `CONFIRMED_ADVISORY` | Prototype Pollution in nconf | GHSA-6xwr-q98w-rvg7 | `RUNTIME` | `ev-nodegoat-nconf@0.10.0` |
| **P1** | `finding-nodegoat-041` | `CONFIRMED_ADVISORY` | Prototype Pollution in nconf | GHSA-6xwr-q98w-rvg7 | `RUNTIME` | `ev-nodegoat-nconf@0.6.9` |
| **P1** | `finding-nodegoat-042` | `CONFIRMED_ADVISORY` | path-to-regexp vulnerable to Regular Expression Denial of Se | GHSA-37ch-88jc-xwx2, GHSA-9wv6-86v2-598j, GHSA-rhx6-c78j-4q9w | `RUNTIME` | `ev-nodegoat-path-to-regexp@0.1.7` |
| **P1** | `finding-nodegoat-043` | `CONFIRMED_ADVISORY` | qs vulnerable to Prototype Pollution | GHSA-hrpp-h998-j3pp, GHSA-4mjr-xmp4-gh2g, GHSA-6rw7-vpxm-498p | `RUNTIME` | `ev-nodegoat-qs@6.5.2` |
| **P1** | `finding-nodegoat-044` | `CONFIRMED_ADVISORY` | semver vulnerable to Regular Expression Denial of Service | GHSA-c2qf-rxjj-qqgw | `RUNTIME` | `ev-nodegoat-semver@5.6.0` |
| **P1** | `finding-nodegoat-045` | `CONFIRMED_ADVISORY` | semver vulnerable to Regular Expression Denial of Service | GHSA-c2qf-rxjj-qqgw | `RUNTIME` | `ev-nodegoat-semver@5.7.0` |
| **P1** | `finding-nodegoat-046` | `CONFIRMED_ADVISORY` | Arbitrary local file read vulnerability during template rend | GHSA-2rq5-699j-x7p6 | `RUNTIME` | `ev-nodegoat-swig@1.4.2` |
| **P1** | `finding-nodegoat-047` | `CONFIRMED_ADVISORY` | Regular Expression Denial of Service in uglify-js | GHSA-c9f4-xj24-8jqx | `RUNTIME` | `ev-nodegoat-uglify-js@2.4.24` |
| **P1** | `finding-nodegoat-048` | `CONFIRMED_ADVISORY` | Prototype Pollution in y18n | GHSA-c4w7-xm78-47vh | `RUNTIME` | `ev-nodegoat-y18n@3.2.1` |
| **P1** | `finding-nodegoat-049` | `CONFIRMED_ADVISORY` | adm-zip: Uncontrolled memory allocation via the declared unc | GHSA-7q85-xj36-vmfc, GHSA-8238-w5pm-2374, GHSA-rcw4-f5rp-g42v, GHSA-xcpc-8h2w-3j85, GHSA-j5f4-cc29-5x44, GHSA-p634-w6r4-rjp2, GHSA-3v6h-hqm4-2rg6, GHSA-c6fg-446q-cg94 | `BUILD` | `ev-nodegoat-adm-zip@0.4.4` |
| **P1** | `finding-nodegoat-050` | `CONFIRMED_ADVISORY` | Inefficient Regular Expression Complexity in chalk/ansi-rege | GHSA-93q8-gq69-wqmw | `BUILD` | `ev-nodegoat-ansi-regex@3.0.0` |
| **P1** | `finding-nodegoat-051` | `CONFIRMED_ADVISORY` | Prototype Pollution in async | GHSA-fwr7-v2mv-hh25 | `BUILD` | `ev-nodegoat-async@2.6.1` |

*(Remaining 83 findings omitted from summary table; consult `report.json` for full list)*

## 4. Artifact Integrity & Provenance

| Artifact File | Availability Status |
|---|---|
| `metadata.json` | `C:\amrita_uni\Projects\BGSW_Team15\BGSW_Team15\runs\day1-nodegoat\metadata.json` |
| `module_index.json` | `C:\amrita_uni\Projects\BGSW_Team15\BGSW_Team15\runs\day1-nodegoat\module_index.json` |
| `graph.json` | `C:\amrita_uni\Projects\BGSW_Team15\BGSW_Team15\runs\day1-nodegoat\graph.json` |
| `evidence.jsonl` | `NOT_AVAILABLE` |
| `findings.json` | `C:\amrita_uni\Projects\BGSW_Team15\BGSW_Team15\runs\day1-nodegoat\findings.json` |
| `sbom.cdx.json` | `C:\amrita_uni\Projects\BGSW_Team15\BGSW_Team15\runs\day1-nodegoat\sbom.cdx.json` |
| `proposals.json` | `NOT_AVAILABLE` |
| `validation.json` | `NOT_AVAILABLE` |

## 5. Security Limitations & Non-Negotiable Honesty

- Discovery depends on manifest/lockfile completeness; undeclared vendored binaries are not inspected.
- Reachability and execution evidence are marked as observed or potential based on entrypoints and scripts.
- Fix proposals require human authorization and isolated build/rescan validation before acceptance.
