# Verified local toolchain

Recorded on 2026-11-23 for the Day 1 integration run. These are measured versions,
not installation promises for another workstation.

| Tool | Verified version | Day 1 use |
|---|---:|---|
| Python | 3.11.9 | CLI, tests and UI |
| Pydantic | 2.14.1 | Canonical schema validation |
| pytest | 9.1.1 | Acceptance suite |
| Streamlit | 1.67.0 | Read-only reviewer UI |
| Syft | 1.57.2 | Source SBOM |
| Grype | 0.122.1 | Advisory scan; DB built 2026-11-23T06:28:32Z |
| Git | 2.48.1.windows.1 | Pinned public repository intake |

Trivy and osv-scanner were not installed. Docker CLI was present but no container
image was built or scanned; the Day 1 non-source surface is GitHub Actions CI.
