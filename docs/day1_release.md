# Day 1 Release Sign-off Record (§16.5)

```yaml
release: day1-integrated
main_commit: a1aec8c9d5911a48257e44415a182d192810d301
contract_schema_version: '1.0'
members_merged: [A, B, C, D, E]
real_sample_repo: https://github.com/OWASP/NodeGoat#c5cb68a7084e4ae7dcc60e6a98768720a81841e8
scan_run_dir: runs/day1-nodegoat
manifest_count: 1
module_count: 1
resolved_component_count: 1091
edge_count: 1977
known_advisory_ids:
  - GHSA-23c5-xmqv-rm74
  - GHSA-23hp-3jrh-7fpw
  - GHSA-27r3-jxmh-p828
  - GHSA-282f-qqgm-c34q
  - GHSA-2883-xcg3-v3hh
  - GHSA-29mw-wpgm-hmr9
  - GHSA-2cf5-4w76-r9qv
  - GHSA-2g4f-4pwh-qvx6
  - GHSA-2m39-62fm-q8r3
  - GHSA-2pr6-76vf-7546
non_cve_rule_ids:
  - RULE-SUSP-UNPINNED
ci_or_image_inspected: CI
coverage_status: RESOLVED
tests_passed: 21
tests_failed: 0
tests_skipped: 1
llm_mode: disabled
external_tools_unavailable: []
limitations:
  - Reachability is estimated via entrypoints and script indicators; dynamic proof of exploitability is not guaranteed.
  - Fix proposals require human authorization and isolated sandbox rescan before merging.
  - Image SBOM is marked NOT_RUN in Day 1 scope; CI workflow analysis is the primary non-source surface.
reviewers: [PK, DX, RY]
```

## Release Summary
- **M1 Dependency Graph:** 1,091 components, 1,977 edges generated from clean lockfile resolution without executing untrusted scripts.
- **Day 1 Security Findings:** 131 vulnerable packages, 196 distinct OSV advisories attached to resolved occurrences with provenance paths.
- **Suspicious Changes:** Non-registry tarball dependency and unpinned `latest` dependency flagged with source lines and hashes.
- **Reviewer Interface:** Streamlit app launched via `scripts/run_ui.bat` or `python -m streamlit run ui/app.py`.
- **Release Verification:** All §16/21 checks executed via `python scripts/release_checklist.py` with 0 failures.

