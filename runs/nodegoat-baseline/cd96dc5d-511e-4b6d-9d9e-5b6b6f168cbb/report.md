# Guardian Supply Chain Security Report

> **Scan ID:** `cd96dc5d-511e-4b6d-9d9e-5b6b6f168cbb` | **Status:** `COMPLETE` | **Source:** `GIT_PUBLIC`
> **Repository:** `https://github.com/OWASP/NodeGoat.git` | **Commit:** `91d8adb963f5de15ccadc2b15a1b6aa67c624c4e`

---

## 1. Supply Chain Inventory & Coverage Summary

| Metric | Count | Note |
|---|---|---|
| Total Modules | 1 | Monorepo/sub-projects detected |
| Resolved Modules | 1 | Full lockfile resolution |
| Partial Modules | 0 | Unresolved dependencies present |
| Total Components | 1466 | Unique package occurrences |
| Dependency Edges | 2272 | Direct & transitive graph relationships |

## 2. Findings Summary

- **Total Security Findings:** 97
- **Priority Breakdown:** P0: 0, P1: 62, P2: 20, P3: 9
- **Classifications:**
  - `CONFIGURATION_WEAKNESS`: 6
  - `CONFIRMED_ADVISORY`: 91

## 3. Detailed Security Findings

| Priority | Finding ID | Classification | Title | Advisory / Rule | Stage | Evidence |
|---|---|---|---|---|---|---|
| **NEEDS_REVIEW** | `fnd:480441423c6316e809b8` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/setup-node@v1 (version-tag) | D5-UNPINNED-ACTION | `CI` | `ev:204dee2265b14be494d9` |
| **NEEDS_REVIEW** | `fnd:4e0140f0558315a7f829` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/checkout@v2 (version-tag) i | D5-UNPINNED-ACTION | `CI` | `ev:689265e09eaf8135f8f0` |
| **NEEDS_REVIEW** | `fnd:909bc8c6af4176e96278` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/cache@v2 (version-tag) in . | D5-UNPINNED-ACTION | `CI` | `ev:ac86d4a4b77426f2de84` |
| **NEEDS_REVIEW** | `fnd:b6d37c32f97446de1311` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/checkout@v2 (version-tag) i | D5-UNPINNED-ACTION | `CI` | `ev:f24b481b50bfec59a803` |
| **NEEDS_REVIEW** | `fnd:bc3f1ce25aa7e37802b0` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/setup-node@v1 (version-tag) | D5-UNPINNED-ACTION | `CI` | `ev:9e585eee667b2e60dcc9` |
| **NEEDS_REVIEW** | `fnd:d6a9c8d7e3d71221ac1a` | `CONFIGURATION_WEAKNESS` | Mutable action reference actions/upload-artifact@v2 (version | D5-UNPINNED-ACTION | `CI` | `ev:79444ed1767b15b589f5` |
| **P1** | `fnd:08afe21a4775e8794f42` | `CONFIRMED_ADVISORY` | debug@2.2.0: CVE-2017-20165 (High) | GHSA-9vvw-cc9w-f27h | `UNKNOWN` | `ev:e63e728649f460094018, ev:8dd3280f0bf150aacc2e6266, ev:bc259c9e68b4b36652b3bbb6, ev:dbbca5d1a4bfaa475188f139, ev:e355b17e702fe4711e49655a` |
| **P1** | `fnd:1b62e97478285d5742a3` | `CONFIRMED_ADVISORY` | kind-of@6.0.2: CVE-2019-20149 (High) | GHSA-6c8f-qphg-qjgp | `UNKNOWN` | `ev:4dbc183cfe1f2bfd3dee, ev:150d0be6898915457dc52925, ev:1f6379808d7c5a690dee8da6, ev:227ac56e56372312ec595f6a, ev:6dd074656e794cb5bb71d10f, ev:7c3153a440fdae8fac977015, ev:84585529b119b22091de3c08, ev:ae7684337165043d1d0afe17, ev:b72bce890980e705ed12027d` |
| **P1** | `fnd:1bbb065dc0d1d690fe2a` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-32803 (High) | GHSA-r628-mhmh-qjhw | `UNKNOWN` | `ev:030be100699fae23f7b8, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:1f138ea9365c06c8beb4` | `CONFIRMED_ADVISORY` | brace-expansion@1.1.11: CVE-2026-69152 (High) | GHSA-rgw5-rvv9-x895 | `UNKNOWN` | `ev:bb041228c9e81616a20f, ev:6b46054fe0fb459f8e7c, ev:1a2c819c05e38dd5816c7ffd, ev:3c364c7e0e38873c39c9ac36` |
| **P1** | `fnd:20eb4cbc4b7fa23554a5` | `CONFIRMED_ADVISORY` | qs@6.5.2: CVE-2022-24999 (High) | GHSA-hrpp-h998-j3pp | `UNKNOWN` | `ev:60668aa6dc36744852dc, ev:46213c3153f31c8e9ce6dad7` |
| **P1** | `fnd:22d5e6f02e54111b4eaf` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-23950 (High) | GHSA-r6q2-hw4h-h46w | `UNKNOWN` | `ev:971e679ef243d59ded60, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:26388e0adc1314dfdf57` | `CONFIRMED_ADVISORY` | marked@0.3.5: CVE-2022-21681 (High) | GHSA-5v2h-r2cx-5xgj | `UNKNOWN` | `ev:1cfcc97b1aa06174f7a0, ev:9f9cf4f58f1be507a94cd4bc` |
| **P1** | `fnd:283e42dea24db7256da4` | `CONFIRMED_ADVISORY` | fsevents@1.2.9: GHSA-xv2f-5jw4-v95m (Critical) | GHSA-xv2f-5jw4-v95m | `UNKNOWN` | `ev:d120ef38647465900dad, ev:bb57af811d75e678bc5de9a8` |
| **P1** | `fnd:2a7bd68b11292c77ffe3` | `CONFIRMED_ADVISORY` | path-to-regexp@0.1.7: CVE-2026-4867 (High) | GHSA-37ch-88jc-xwx2 | `UNKNOWN` | `ev:65b140b8afad5ec4a9c1, ev:b8011c036499bccc4d3e3db4` |
| **P1** | `fnd:2d593e0b4b59a9fe3e06` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-59874 (High) | GHSA-8x88-c5mf-7j5w | `UNKNOWN` | `ev:91d0c71e389a65ae9d34, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:34edfd135f9b65688b71` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-32804 (High) | GHSA-3jfq-g458-7qm9 | `UNKNOWN` | `ev:4bc4dd6c175457ee6ad6, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:3623bcb892f1c7ca5bbe` | `CONFIRMED_ADVISORY` | swig@1.4.2: CVE-2023-25345 (High) | GHSA-2rq5-699j-x7p6 | `UNKNOWN` | `ev:c44568b76ca2dbf299fb, ev:174b848fc03c430a47fae953` |
| **P1** | `fnd:37d763de9b926e9ffd18` | `CONFIRMED_ADVISORY` | underscore@1.9.1: CVE-2026-27601 (High) | GHSA-qpx9-hpmf-5gmw | `UNKNOWN` | `ev:249262fa9d19223ef1c1, ev:bb34f17dea17eb5383d0342e` |
| **P1** | `fnd:3d3669585d79ad194393` | `CONFIRMED_ADVISORY` | path-to-regexp@0.1.7: CVE-2024-45296 (High) | GHSA-9wv6-86v2-598j | `UNKNOWN` | `ev:bd9bf708192ac9d295bb, ev:b8011c036499bccc4d3e3db4` |
| **P1** | `fnd:3f761f180c558f0b4c7e` | `CONFIRMED_ADVISORY` | bson@1.0.9: CVE-2020-7610 (Critical) | GHSA-v8w9-2789-6hhr | `UNKNOWN` | `ev:9f9afeb3feb81e8f304e, ev:a22bacf0597bc8df21d2badf` |
| **P1** | `fnd:42e9f88a4cd28a514d29` | `CONFIRMED_ADVISORY` | braces@2.3.2: CVE-2024-4068 (High) | GHSA-grv7-fg5c-xmjg | `UNKNOWN` | `ev:39edd0869a87b5c07b96, ev:598c62a17ec30c7c43d29ec2, ev:b62693f00dd9ff24f01873b5` |
| **P1** | `fnd:498d9f485c0e0d6f3c3e` | `CONFIRMED_ADVISORY` | semver@5.7.0: CVE-2022-25883 (High) | GHSA-c2qf-rxjj-qqgw | `UNKNOWN` | `ev:5008ed3cc193b5d9622b, ev:4af203db1f4e40a7da90775b` |
| **P1** | `fnd:4ceed8e9bb3c7adebbb2` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-73566 (High) | GHSA-r292-9mhp-454m | `UNKNOWN` | `ev:b4ac665f14d88e193d50, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:4e6f86bf518d929e0c7f` | `CONFIRMED_ADVISORY` | path-to-regexp@0.1.7: CVE-2024-52798 (High) | GHSA-rhx6-c78j-4q9w | `UNKNOWN` | `ev:702908974edd431d30e2, ev:b8011c036499bccc4d3e3db4` |
| **P1** | `fnd:50388c62f384c975693d` | `CONFIRMED_ADVISORY` | brace-expansion@1.1.11: CVE-2026-14257 (High) | GHSA-mh99-v99m-4gvg | `UNKNOWN` | `ev:ca3cd0e72b85849f4e70, ev:e4ec2d78a88dbd2cee1c, ev:1a2c819c05e38dd5816c7ffd, ev:3c364c7e0e38873c39c9ac36` |
| **P1** | `fnd:55f1d4816a510a5395be` | `CONFIRMED_ADVISORY` | set-value@0.4.3: CVE-2019-10747 (Critical) | GHSA-4g88-fppr-53pp | `UNKNOWN` | `ev:67164a91f4e30853110b, ev:afd6d1515ba2e179ebdf8e9f` |
| **P1** | `fnd:590434f284f5f0e3d590` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37713 (High) | GHSA-5955-9wpr-37jh | `UNKNOWN` | `ev:602a25f2cfc9835ea3c7, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:5f9dc115b5c2756188a4` | `CONFIRMED_ADVISORY` | decode-uri-component@0.2.0: CVE-2022-38900 (High) | GHSA-w573-4hg7-7wgq | `UNKNOWN` | `ev:78fa8246de8f3dcc45e0, ev:c3d153f8342c1ab15c6a1c5e` |
| **P1** | `fnd:609b1d230283b28577a7` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-31802 (High) | GHSA-9ppj-qmqm-q256 | `UNKNOWN` | `ev:61e36c1507429247b2c8, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:6660f46c087d2a986400` | `CONFIRMED_ADVISORY` | minimist@0.0.10: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:76e11ec347c8b95f9105, ev:3ac0b4ba3b31ee6e8f155998` |
| **P1** | `fnd:6a7b3a8980e3a53a406b` | `CONFIRMED_ADVISORY` | minimist@1.2.0: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:b64950af166c93006ede, ev:26b0c4c65925f85e18002cf9, ev:2bb1a95b5ceac6bc3380a3e3, ev:ac9626021b628715fb9e7309, ev:ba932cfcf110f3e8798eebfc, ev:c7e5b63c087fef9fd3333ebc, ev:e6535b518a5043a6ceec8bdb` |
| **P1** | `fnd:71e662f1e4cfc5a527d2` | `CONFIRMED_ADVISORY` | y18n@3.2.1: CVE-2020-7774 (High) | GHSA-c4w7-xm78-47vh | `UNKNOWN` | `ev:8deef9c57017e1be8f0a, ev:30e7c54b49a360710c8e24e1, ev:9f80d6c8762056edd18c235f` |
| **P1** | `fnd:734600d501103dc53339` | `CONFIRMED_ADVISORY` | minimist@0.0.8: CVE-2021-44906 (Critical) | GHSA-xvch-5gv4-984h | `UNKNOWN` | `ev:d9b02335306ee9179bb8, ev:5e97e9a229e8255e0319, ev:1e3f14bd64063e0327bea9f7, ev:2f4d243115c18d6f1629ea91, ev:4133ed93e802980c0acb9b2d, ev:69a1abc144f771d1fe47a03c` |
| **P1** | `fnd:78428756487e6fe00af5` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-27903 (High) | GHSA-7r86-cg39-jmmj | `UNKNOWN` | `ev:19efd66e2c9273a10839, ev:7e41677c0e35c8cb69ea, ev:3de5f242e592edcfbe506267, ev:f103ef4d9dc5edbffa699a78` |
| **P1** | `fnd:804b5e4066713bc3617f` | `CONFIRMED_ADVISORY` | proxy-addr@2.0.4: CVE-2026-90711 (Critical) | GHSA-jqcg-44mw-7w3h | `UNKNOWN` | `ev:38397681a4a1527d4b08, ev:b0d781a5e5d3c890f4a7ece7` |
| **P1** | `fnd:806b50a7baff8d0b7c28` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-26960 (High) | GHSA-83g3-92jg-28cx | `UNKNOWN` | `ev:78094d7ad629c6e53ce8, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:8297e69d44af964cde3a` | `CONFIRMED_ADVISORY` | marked@0.3.5: CVE-2017-16114 (High) | GHSA-x5pg-88wf-qq4p | `UNKNOWN` | `ev:ab53c6e70ca6f47a91c0, ev:9f9cf4f58f1be507a94cd4bc` |
| **P1** | `fnd:8860e1256a1c64662785` | `CONFIRMED_ADVISORY` | marked@0.3.5: CVE-2022-21680 (High) | GHSA-rrrm-qjm4-v8hf | `UNKNOWN` | `ev:14d329d959756bc4594d, ev:9f9cf4f58f1be507a94cd4bc` |
| **P1** | `fnd:8eadef6e9aa74dd90e42` | `CONFIRMED_ADVISORY` | brace-expansion@1.1.11: CVE-2026-102278 (High) | GHSA-qhr7-859c-m2p7 | `UNKNOWN` | `ev:519ecd5820bc65e3b488, ev:8ade27473664843f149f, ev:1a2c819c05e38dd5816c7ffd, ev:3c364c7e0e38873c39c9ac36` |
| **P1** | `fnd:9204c88afc35eebb8339` | `CONFIRMED_ADVISORY` | mongodb@2.2.36: GHSA-mh5c-679w-hh4r (High) | GHSA-mh5c-679w-hh4r | `UNKNOWN` | `ev:5bf941240ebab071487b, ev:d433fe0ac70fe0a1851b70dd` |
| **P1** | `fnd:94c4609868608475577b` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37701 (High) | GHSA-9r2w-394v-53qc | `UNKNOWN` | `ev:b1e04e0f85502154569e, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:9e76985feb484e1cb055` | `CONFIRMED_ADVISORY` | nconf@0.10.0: CVE-2022-21803 (High) | GHSA-6xwr-q98w-rvg7 | `UNKNOWN` | `ev:9d3e7ed66ef2c7d53c27, ev:5de20b6bdf2c3562879f3bf3` |
| **P1** | `fnd:a17ed4ee42a9e600bf19` | `CONFIRMED_ADVISORY` | underscore@1.9.1: CVE-2021-23358 (Critical) | GHSA-cf4h-3jhx-xvhq | `UNKNOWN` | `ev:3301b3cb59bdcef79887, ev:bb34f17dea17eb5383d0342e` |
| **P1** | `fnd:a62e0db81952d1556c51` | `CONFIRMED_ADVISORY` | fsevents@1.2.9: CVE-2023-45311 (Critical) | GHSA-8r6j-v8pm-fqw3 | `UNKNOWN` | `ev:03345cd50baefd637c5e, ev:bb57af811d75e678bc5de9a8` |
| **P1** | `fnd:a881b846fc9e5b4ff5b9` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2021-37712 (High) | GHSA-qq89-hq3f-393p | `UNKNOWN` | `ev:ff771925a3a1b41d35e4, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:a9f50f7e814a5d680db6` | `CONFIRMED_ADVISORY` | tar@4.4.8: CVE-2026-24842 (High) | GHSA-34x7-hfp2-rc4v | `UNKNOWN` | `ev:ebb610276fe794766e98, ev:e753b20e31922d27a055d7cc` |
| **P1** | `fnd:aa391cfe0ee96d49a14f` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-26996 (High) | GHSA-3ppc-4f35-3m26 | `UNKNOWN` | `ev:c28d940fe4d84565aff8, ev:c308d4b967d69864ded6, ev:3de5f242e592edcfbe506267, ev:f103ef4d9dc5edbffa699a78` |
| **P1** | `fnd:ad95f8bc25114d79cf60` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2026-27904 (High) | GHSA-23c5-xmqv-rm74 | `UNKNOWN` | `ev:89f1d71ffe76f19775da, ev:4cef51365ee6b8d41f7d, ev:3de5f242e592edcfbe506267, ev:f103ef4d9dc5edbffa699a78` |
| **P1** | `fnd:afb76342a255d40929d3` | `CONFIRMED_ADVISORY` | minimatch@3.0.4: CVE-2022-3517 (High) | GHSA-f8q6-p94x-37v3 | `UNKNOWN` | `ev:1ce2e09c28dc78ee32a8, ev:6d685e66d223461bd87e, ev:3de5f242e592edcfbe506267, ev:f103ef4d9dc5edbffa699a78` |

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
- SYFT_RELATIONSHIPS: edges; syft packages=381 lockfile packages=1081
- SCANNER_CONFLICT: 1 package(s) only in Syft, 701 only in lockfile; both observations retained (graph edges come from the lockfile)
