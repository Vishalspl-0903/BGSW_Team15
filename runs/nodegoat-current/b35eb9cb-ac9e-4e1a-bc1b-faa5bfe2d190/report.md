# Guardian Supply Chain Security Report

> **Scan ID:** `b35eb9cb-ac9e-4e1a-bc1b-faa5bfe2d190` | **Status:** `COMPLETE` | **Source:** `GIT_PUBLIC`
> **Repository:** `https://github.com/OWASP/NodeGoat.git` | **Commit:** `c5cb68a7084e4ae7dcc60e6a98768720a81841e8`

---

## 1. Supply Chain Inventory & Coverage Summary

| Metric | Count | Note |
|---|---|---|
| Total Modules | 1 | Monorepo/sub-projects detected |
| Resolved Modules | 1 | Full lockfile resolution |
| Partial Modules | 0 | Unresolved dependencies present |
| Total Components | 1479 | Unique package occurrences |
| Dependency Edges | 2296 | Direct & transitive graph relationships |

## 2. Findings Summary

- **Total Security Findings:** 97
- **Priority Breakdown:** P0: 0, P1: 62, P2: 20, P3: 9
- **Classifications:**
  - `CONFIGURATION_WEAKNESS`: 6
  - `CONFIRMED_ADVISORY`: 91

## 3. Detailed Security Findings

| Priority | Finding ID | Classification | Title | Advisory / Rule | Stage | Evidence |
|---|---|---|---|---|---|---|
| **NEEDS_REVIEW** | `fnd:6d5b5b221f8f343ad0a1` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/cache@v2 (version-tag) in . | D5-UNPINNED-ACTION | `CI` | `ev:170cb0b22e03a81398d3` |
| **NEEDS_REVIEW** | `fnd:7ab43aa8686922fc8bbe` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/checkout@v2 (version-tag) i | D5-UNPINNED-ACTION | `CI` | `ev:5a872200d3f01da6ee24` |
| **NEEDS_REVIEW** | `fnd:843b3b50ae146d5d45bf` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/upload-artifact@v2 (version | D5-UNPINNED-ACTION | `CI` | `ev:3a60dbbd5d4aeab7d30b` |
| **NEEDS_REVIEW** | `fnd:9dc7d4dc23801c47a993` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/setup-node@v1 (version-tag) | D5-UNPINNED-ACTION | `CI` | `ev:f216761f2936c8b4f880` |
| **NEEDS_REVIEW** | `fnd:b4d7f28686f8e412239c` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/setup-node@v1 (version-tag) | D5-UNPINNED-ACTION | `CI` | `ev:e10b198fdc6815477b99` |
| **NEEDS_REVIEW** | `fnd:ec6531edb013512990fd` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/checkout@v2 (version-tag) i | D5-UNPINNED-ACTION | `CI` | `ev:6bd606cedd5d75daa2a6` |
| **P1** | `fnd:00f87617d3a5a1b638b0` | `CONFIRMED_ADVISORY` | swig@1.4.2: CVE-2023-25345 (High) | GHSA-2rq5-699j-x7p6 | `UNKNOWN` | `ev:7b1319792fc93a67a84f, ev:d549bf85eb7e132fe7f0c96b` |
| **P1** | `fnd:01085124b4ade3e307be` | `CONFIRMED_ADVISORY` | i@0.3.6: CVE-2021-3820 (High) | GHSA-x55w-vjjp-222r | `UNKNOWN` | `ev:e1f3303f7c6eb836f39e, ev:9a1033c7c71ad6190a5d1739` |
| **P1** | `fnd:027df9942d9cca2e2cb6` | `CONFIRMED_ADVISORY` | uglify-js@2.4.24: CVE-2015-8858 (High) | GHSA-c9f4-xj24-8jqx | `UNKNOWN` | `ev:3a7448a05346368c618c, ev:036937cd1567c616cffe578e` |
| **P1** | `fnd:05c78286b32e59ea2e1d` | `CONFIRMED_ADVISORY` | marked@0.3.5: CVE-2017-16114 (High) | GHSA-x5pg-88wf-qq4p | `UNKNOWN` | `ev:6f3fc9d882ceee2b6ed3, ev:f7d442a084bb6297c9100b79` |
| **P1** | `fnd:0943d12c2e5948668bb9` | `CONFIRMED_ADVISORY` | minimist@0.0.8: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:df7af296c88b04a19a2e, ev:7f34a84164f4ffbab680, ev:1d41092398944b704cf470d8, ev:5c231881fc12ec80694d5f40, ev:7b64b428c44d0ee32866261c, ev:fa6d88818ee430cf7ce9a3e1` |
| **P1** | `fnd:09f16144b2ca6e38eb87` | `CONFIRMED_ADVISORY` | brace-expansion@1.1.11: CVE-2026-69152 (High) | GHSA-rgw5-rvv9-x895 | `UNKNOWN` | `ev:fdc7fecf5ea8b918bcdb, ev:a904f2e555472ea830c0, ev:1a4a8e451c040f62ff61ac68, ev:f1f3bebc37ee54b8b05bc139` |
| **P1** | `fnd:0d1e2e643a5fb3fb7466` | `CONFIRMED_ADVISORY` | qs@6.5.2: CVE-2022-24999 (High) | GHSA-hrpp-h998-j3pp | `UNKNOWN` | `ev:9715476e651ad32b8c9a, ev:02932e81d6b3a3a099ad7678` |
| **P1** | `fnd:1c8ed11828b03b2c076a` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-32804 (High) | GHSA-3jfq-g458-7qm9 | `UNKNOWN` | `ev:cf29a0ad3d3f58495c29, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:2961aa32513d79fdb9ec` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-26996 (High) | GHSA-3ppc-4f35-3m26 | `UNKNOWN` | `ev:52b828349d9772cfa584, ev:fd360bc4f7f9035b0dc2, ev:67ebafb32889e37dd1cc9745, ev:a6ca5fa12479fe1fdcf90b06` |
| **P1** | `fnd:29ca6a2d877207d603c1` | `CONFIRMED_ADVISORY` | semver@5.7.0: CVE-2022-25883 (High) | GHSA-c2qf-rxjj-qqgw | `UNKNOWN` | `ev:f360e0ff277ed3e2895b, ev:f2eb6798f78dcc2eafea0697` |
| **P1** | `fnd:2f21e843bdccd9cc60dc` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-59874 (High) | GHSA-8x88-c5mf-7j5w | `UNKNOWN` | `ev:e00f755826047d26fb82, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:3256997dcfdc20108618` | `CONFIRMED_ADVISORY` | fsevents@1.2.9: CVE-2023-45311 (Critical) | GHSA-8r6j-v8pm-fqw3 | `UNKNOWN` | `ev:707a8494410b4a91351c, ev:ab4e4f96ec1c8f86f417393f` |
| **P1** | `fnd:3412dbed717108c8c5f4` | `CONFIRMED_ADVISORY` | minimist@0.0.10: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:87b3e97040ef79ec431c, ev:293080f448afbc28993d597e` |
| **P1** | `fnd:37378d71b24dc657b3d8` | `CONFIRMED_ADVISORY` | path-to-regexp@0.1.7: CVE-2024-52798 (High) | GHSA-rhx6-c78j-4q9w | `UNKNOWN` | `ev:67ddfb7b27850cbf348f, ev:0f5f50841aa96e50806aab8f` |
| **P1** | `fnd:3d462fe7cbeadc07d424` | `CONFIRMED_ADVISORY` | body-parser@1.18.3: CVE-2024-45590 (High) | GHSA-qwcr-r2fm-qrc7 | `UNKNOWN` | `ev:4cee9f220946bb3a0784, ev:6a67ee723cbed23ae068e36b` |
| **P1** | `fnd:3d7235dedbd87a9dd936` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-73566 (High) | GHSA-r292-9mhp-454m | `UNKNOWN` | `ev:02fc5bc28307edbf2ce2, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:409e5464a512cca80f3b` | `CONFIRMED_ADVISORY` | path-to-regexp@0.1.7: CVE-2024-45296 (High) | GHSA-9wv6-86v2-598j | `UNKNOWN` | `ev:2c7c0bb5c755177d20c4, ev:0f5f50841aa96e50806aab8f` |
| **P1** | `fnd:4809d9c2da87eeb6f95c` | `CONFIRMED_ADVISORY` | set-value@0.4.3: CVE-2021-23440 (High) | GHSA-4jqc-8m5r-9rpr | `UNKNOWN` | `ev:d8a73f4a50ff64cc3e7b, ev:9f953261af459ca7d8c857bd` |
| **P1** | `fnd:567e88b2bdc89e54079e` | `CONFIRMED_ADVISORY` | body-parser@1.18.3: CVE-2026-111181 (High) | GHSA-27r3-jxmh-p828 | `UNKNOWN` | `ev:d2018303832b516be1df, ev:6a67ee723cbed23ae068e36b` |
| **P1** | `fnd:5783fc29a82efef4a052` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-26960 (High) | GHSA-83g3-92jg-28cx | `UNKNOWN` | `ev:a1595c018754c9726016, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:57b6e4ca799ed2efb512` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-24842 (High) | GHSA-34x7-hfp2-rc4v | `UNKNOWN` | `ev:e44762a353aa051644ed, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:5da0d9be03d6ab6c21b3` | `CONFIRMED_ADVISORY` | set-value@0.4.3: CVE-2019-10747 (Critical) | GHSA-4g88-fppr-53pp | `UNKNOWN` | `ev:7b9950c0b6c1590fa63b, ev:9f953261af459ca7d8c857bd` |
| **P1** | `fnd:6241f06580678fcb5bb8` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-23745 (High) | GHSA-8qq5-rm4j-mr97 | `UNKNOWN` | `ev:331aff29659037e46ff7, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:64767ea2ff97c2529488` | `CONFIRMED_ADVISORY` | underscore@1.9.1: CVE-2021-23358 (Critical) | GHSA-cf4h-3jhx-xvhq | `UNKNOWN` | `ev:c1b60ac6c2e3e1f176ac, ev:3d771b9abe7658b52fccf30e` |
| **P1** | `fnd:64aabc9263de2c3fa7d5` | `CONFIRMED_ADVISORY` | fsevents@1.2.9: GHSA-xv2f-5jw4-v95m (Critical) | GHSA-xv2f-5jw4-v95m | `UNKNOWN` | `ev:b8f2a318dc8ada9c65bb, ev:ab4e4f96ec1c8f86f417393f` |
| **P1** | `fnd:69a0b433e79a4b840784` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-23950 (High) | GHSA-r6q2-hw4h-h46w | `UNKNOWN` | `ev:491a7b68e900e2873afb, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:6af56b278583ff796d86` | `CONFIRMED_ADVISORY` | marked@0.3.5: CVE-2022-21681 (High) | GHSA-5v2h-r2cx-5xgj | `UNKNOWN` | `ev:698c8480f337f866fb56, ev:f7d442a084bb6297c9100b79` |
| **P1** | `fnd:6ba5662806ff0de1a1a6` | `CONFIRMED_ADVISORY` | debug@2.2.0: CVE-2017-20165 (High) | GHSA-9vvw-cc9w-f27h | `UNKNOWN` | `ev:35dcdafc3292fd62f1fa, ev:9f3f3cad562c35aaa8a6b212, ev:a0a319fdf456f16b0426a7b4, ev:bf719ad7f03a2af2e6b3a927, ev:e0872e7408a570cc683395ce` |
| **P1** | `fnd:6d8ad580750e291cce75` | `CONFIRMED_ADVISORY` | brace-expansion@1.1.11: CVE-2026-14257 (High) | GHSA-mh99-v99m-4gvg | `UNKNOWN` | `ev:78ecd868c3dde2e08817, ev:3eee85f013374b08c4de, ev:1a4a8e451c040f62ff61ac68, ev:f1f3bebc37ee54b8b05bc139` |
| **P1** | `fnd:707525ff3c1d07644c37` | `CONFIRMED_ADVISORY` | set-value@2.0.0: CVE-2021-23440 (High) | GHSA-4jqc-8m5r-9rpr | `UNKNOWN` | `ev:c43c5668397ce80a1166, ev:b3e82c807923198ee0f999c5` |
| **P1** | `fnd:7163e21545c55b52baf3` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37701 (High) | GHSA-9r2w-394v-53qc | `UNKNOWN` | `ev:ccd2cb7a3f1e7bab34c2, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:744d44d33bbc4d2835ea` | `CONFIRMED_ADVISORY` | set-value@2.0.0: CVE-2019-10747 (Critical) | GHSA-4g88-fppr-53pp | `UNKNOWN` | `ev:df684b443711bfbb353c, ev:b3e82c807923198ee0f999c5` |
| **P1** | `fnd:7659ab9ae07aafb3d026` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-27903 (High) | GHSA-7r86-cg39-jmmj | `UNKNOWN` | `ev:b9e70f48d77aef3be72e, ev:ea72775c2839ebc0c859, ev:67ebafb32889e37dd1cc9745, ev:a6ca5fa12479fe1fdcf90b06` |
| **P1** | `fnd:799991fb79012397d375` | `CONFIRMED_ADVISORY` | decode-uri-component@0.2.0: CVE-2026-118664 (High) | GHSA-qr28-fpjm-wq7f | `UNKNOWN` | `ev:c3b44bda0896c29d1165, ev:3e2ef02ca0b6def6cc3a9de7` |
| **P1** | `fnd:7ace8ea60f914b9ef830` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-32803 (High) | GHSA-r628-mhmh-qjhw | `UNKNOWN` | `ev:fd45047f34700fff85dc, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:7ded9353f08e08b5b816` | `CONFIRMED_ADVISORY` | semver@5.6.0: CVE-2022-25883 (High) | GHSA-c2qf-rxjj-qqgw | `UNKNOWN` | `ev:92b95e6ed03d4fd1b1f7, ev:e40dd7221abef1f0660dabdd` |
| **P1** | `fnd:83a6881e9cf79a4755a8` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-59873 (Critical) | GHSA-23hp-3jrh-7fpw | `UNKNOWN` | `ev:f827df043ba90249535a, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:844e8ccc7c116346f872` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-31802 (High) | GHSA-9ppj-qmqm-q256 | `UNKNOWN` | `ev:4531af3cb0b1e0df75f9, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:8fb8bac95ee3b7f439ad` | `CONFIRMED_ADVISORY` | mixin-deep@1.3.1: CVE-2019-10746 (Critical) | GHSA-fhjf-83wg-r2j9 | `UNKNOWN` | `ev:dc0b061d370122da15d7, ev:70a3f3d7dfa6e0f7057d5287` |
| **P1** | `fnd:9109cdb76d704b4d4587` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-27904 (High) | GHSA-23c5-xmqv-rm74 | `UNKNOWN` | `ev:a8ae4a6ee5906e63b8b0, ev:c82ad9334505e6f591ca, ev:67ebafb32889e37dd1cc9745, ev:a6ca5fa12479fe1fdcf90b06` |
| **P1** | `fnd:92bcdc636899450b17d1` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37712 (High) | GHSA-qq89-hq3f-393p | `UNKNOWN` | `ev:5e202094e687c24b6a23, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:96e13c15d447c9ed3ddc` | `CONFIRMED_ADVISORY` | minimist@1.2.5: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:05fc3a0186fcb58a65e3, ev:fe9f9bf0a03858bfe7080777` |
| **P1** | `fnd:97175b86734116f114bb` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-29786 (High) | GHSA-qffp-2rhf-9h96 | `UNKNOWN` | `ev:2fc0f2f31cd1dfccb44e, ev:f12b934e6946e2af69f4bd04` |
| **P1** | `fnd:9979bdae83e132acd237` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37713 (High) | GHSA-5955-9wpr-37jh | `UNKNOWN` | `ev:e2c0033a349eb635fa13, ev:f12b934e6946e2af69f4bd04` |

*(Remaining 47 findings omitted from summary table; consult `report.json` for full list)*

## 4. Artifact Integrity & Provenance

| Artifact File | Availability Status |
|---|---|
| `metadata.json` | `metadata.json` |
| `module_index.json` | `module_index.json` |
| `graph.json` | `graph.json` |
| `evidence.jsonl` | `evidence.jsonl` |
| `findings.json` | `findings.json` |
| `sbom/syft.cdx.json` | `sbom/syft.cdx.json` |

## 5. Security Limitations & Non-Negotiable Honesty

- Discovery depends on manifest/lockfile completeness; undeclared vendored binaries are not inspected.
- A dependency path does not establish runtime reachability or exploitation; no application code was executed.
- Fix proposals require human authorization and isolated build/rescan validation before acceptance.
- lockfile_change_detection: NOT_RUN - no baseline ref supplied; change detection needs a baseline
- SYFT_RELATIONSHIPS: edges; syft packages=381 lockfile packages=1091
- SCANNER_CONFLICT: 1 package(s) only in Syft, 711 only in lockfile; both observations retained (graph edges come from the lockfile)
