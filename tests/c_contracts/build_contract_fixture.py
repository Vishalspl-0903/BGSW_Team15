"""Regenerate ``tests/fixtures/contract_m1`` from its committed source files.

The fixture is a SYNTHETIC controlled test input (project.md §9.3/§28), never a
scan of a real external repository.  Hashes and line numbers are computed from
the exact committed bytes of ``repo/package.json`` and ``repo/package-lock.json``
so evidence cannot drift from the files it cites.

Usage:  python tests/c_contracts/build_contract_fixture.py [--check]
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from guardian.schemas import (  # noqa: E402
    Evidence, FindingsFile, GraphBundle, ModuleIndex, ScanMetadata,
)

FIXTURE = ROOT / "tests" / "fixtures" / "contract_m1"
SCAN_ID = "fixture-m1"
# Time the fixture evidence was authored by Role C (actual authoring time).
RECORDED_AT = "2026-11-23T10:11:49Z"

PACKAGE_JSON = """{
  "name": "contract-m1-fixture",
  "version": "0.0.0",
  "private": true,
  "description": "SYNTHETIC contract fixture for Guardian; fixture package names only",
  "dependencies": {
    "example-web": "1.0.0"
  }
}
"""

PACKAGE_LOCK = """{
  "name": "contract-m1-fixture",
  "version": "0.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "contract-m1-fixture",
      "version": "0.0.0",
      "dependencies": {
        "example-web": "1.0.0"
      }
    },
    "node_modules/example-web": {
      "version": "1.0.0",
      "dependencies": {
        "tiny-helper": "^2.0.0"
      }
    },
    "node_modules/tiny-helper": {
      "version": "2.0.0"
    }
  }
}
"""


def _line_of(text: str, needle: str, after: str | None = None) -> int:
    start = text.index(after) if after else 0
    idx = text.index(needle, start)
    return text.count("\n", 0, idx) + 1


def build() -> dict[str, str]:
    """Return {relative_path: content} for every fixture file."""
    # Structural sanity: the lockfile really encodes the asserted relations.
    lock = json.loads(PACKAGE_LOCK)
    assert lock["packages"][""]["dependencies"]["example-web"] == "1.0.0"
    assert lock["packages"]["node_modules/example-web"]["dependencies"]["tiny-helper"] == "^2.0.0"
    assert lock["packages"]["node_modules/tiny-helper"]["version"] == "2.0.0"
    assert json.loads(PACKAGE_JSON)["dependencies"]["example-web"] == "1.0.0"

    manifest_sha = hashlib.sha256(PACKAGE_JSON.encode("utf-8")).hexdigest()
    lock_sha = hashlib.sha256(PACKAGE_LOCK.encode("utf-8")).hexdigest()
    manifest_line = _line_of(PACKAGE_JSON, '"example-web": "1.0.0"')
    helper_line = _line_of(PACKAGE_LOCK, '"tiny-helper": "^2.0.0"', after='"node_modules/example-web"')

    evidence = [
        Evidence(
            schema_version="1.0", scan_id=SCAN_ID, evidence_id="ev:manifest-root",
            kind="MANIFEST", tool_name="contract-fixture-author", tool_version=None,
            source_path="package.json", json_pointer="/dependencies/example-web",
            line_start=manifest_line, line_end=manifest_line, observed_value="1.0.0",
            raw_artifact="repo/package.json", raw_sha256=manifest_sha,
            observation="SYNTHETIC FIXTURE: root package.json declares direct dependency "
                        "example-web at 1.0.0",
            recorded_at=RECORDED_AT,
        ),
        Evidence(
            schema_version="1.0", scan_id=SCAN_ID, evidence_id="ev:lock-helper",
            kind="LOCKFILE", tool_name="contract-fixture-author", tool_version=None,
            source_path="package-lock.json",
            json_pointer="/packages/node_modules~1example-web/dependencies/tiny-helper",
            line_start=helper_line, line_end=helper_line, observed_value="^2.0.0",
            raw_artifact="repo/package-lock.json", raw_sha256=lock_sha,
            observation="SYNTHETIC FIXTURE: lockfile v3 records example-web@1.0.0 requiring "
                        "tiny-helper ^2.0.0, resolved at node_modules/tiny-helper to 2.0.0",
            recorded_at=RECORDED_AT,
        ),
    ]

    module = {
        "module_id": "mod:root", "relative_path": ".", "ecosystem": "npm",
        "manifests": ["package.json"], "lockfiles": ["package-lock.json"],
        "ci_files": [], "dockerfiles": [], "coverage": "RESOLVED",
        "coverage_reason": "", "scanner_names": ["fixture-lockfile-parser"],
        "file_counts": {"manifests_found": 1, "manifests_scanned": 1,
                        "lockfiles_found": 1, "lockfiles_scanned": 1},
        "scan_stage": {"inventory": "COMPLETE", "graph": "COMPLETE", "advisory": "NOT_RUN",
                       "ci": "NOT_RUN", "container": "NOT_RUN"},
        "artifact_sbom_status": "NOT_RUN",
    }
    common = {"install_stage_indicator": None, "license": None, "artifact_hashes": [],
              "package_source_type": "REGISTRY", "resolved_source_url": None,
              "registry_host": None, "source_scope": "SOURCE", "image_presence": "NOT_CHECKED"}
    graph = GraphBundle.model_validate({
        "schema_version": "1.0", "scan_id": SCAN_ID, "modules": [module],
        "components": [
            {"package_key": "npm:example-web@1.0.0", "ecosystem": "npm", "name": "example-web",
             "resolved_version": "1.0.0", "declared_constraint": "1.0.0",
             "purl": "pkg:npm/example-web@1.0.0", "occurrence_id": "occ:root-example-web",
             "module_id": "mod:root",
             "source_refs": ["package-lock.json#/packages/node_modules~1example-web"],
             "resolution": "RESOLVED", "evidence_ids": ["ev:manifest-root"],
             "dependency_scopes": ["production"], "directness": "DIRECT",
             "manifest_refs": ["package.json"], **common},
            {"package_key": "npm:tiny-helper@2.0.0", "ecosystem": "npm", "name": "tiny-helper",
             "resolved_version": "2.0.0", "declared_constraint": "^2.0.0",
             "purl": "pkg:npm/tiny-helper@2.0.0", "occurrence_id": "occ:root-tiny-helper",
             "module_id": "mod:root",
             "source_refs": ["package-lock.json#/packages/node_modules~1tiny-helper"],
             "resolution": "RESOLVED", "evidence_ids": ["ev:lock-helper"],
             "dependency_scopes": ["production"], "directness": "TRANSITIVE",
             "manifest_refs": [], **common},
        ],
        "edges": [
            {"edge_id": "edge:root-web", "source_id": "mod:root", "target_id": "occ:root-example-web",
             "relationship": "DEPENDS_ON", "evidence_ids": ["ev:manifest-root"], "module_id": "mod:root",
             "resolution": "OBSERVED", "dependency_scope": "production", "declared_constraint": "1.0.0",
             "source_scope": "SOURCE"},
            {"edge_id": "edge:web-helper", "source_id": "occ:root-example-web",
             "target_id": "occ:root-tiny-helper", "relationship": "DEPENDS_ON",
             "evidence_ids": ["ev:lock-helper"], "module_id": "mod:root", "resolution": "OBSERVED",
             "dependency_scope": "production", "declared_constraint": "^2.0.0", "source_scope": "SOURCE"},
        ],
        "coverage_summary": {"total_modules": 1, "resolved_modules": 1, "partial_modules": 0,
                             "declared_only_modules": 0, "unsupported_modules": 0, "failed_modules": 0},
        "warnings": [],
    })
    module_index = ModuleIndex.model_validate({"schema_version": "1.0", "scan_id": SCAN_ID,
                                               "modules": [module]})
    findings = FindingsFile.model_validate({"schema_version": "1.0", "scan_id": SCAN_ID, "findings": []})
    snapshot = hashlib.sha256()
    for rel, content in (("package-lock.json", PACKAGE_LOCK), ("package.json", PACKAGE_JSON)):
        data = content.encode("utf-8")
        snapshot.update(len(rel).to_bytes(8, "big"))
        snapshot.update(rel.encode("utf-8"))
        snapshot.update(data)
    metadata = ScanMetadata.model_validate({
        "schema_version": "1.0", "scan_id": SCAN_ID, "repo_url": "local://fixture/contract-m1",
        "commit_sha": None, "source_kind": "LOCAL_FIXTURE",
        # Hand-authored fixture: no scan ran, so no run times are claimed.
        "started_at": None, "finished_at": None, "status": "COMPLETE",
        "tool_versions": {}, "errors": [],
        "stage_statuses": {"intake": "COMPLETE", "inventory": "COMPLETE", "graph": "COMPLETE",
                           "advisory": "NOT_RUN", "ci": "NOT_RUN", "container": "NOT_RUN"},
        "database_snapshots": {}, "source_snapshot_sha256": snapshot.hexdigest(),
        "scope_capabilities": {
            "source": "SYNTHETIC hand-authored lockfile fixture; no scanner or tool executed",
            "artifact": "NOT_RUN", "ci": "NOT_RUN",
        },
    })

    def dump(model) -> str:
        return json.dumps(model.to_json_dict(), indent=2, ensure_ascii=False) + "\n"

    return {
        "repo/package.json": PACKAGE_JSON,
        "repo/package-lock.json": PACKAGE_LOCK,
        "metadata.json": dump(metadata),
        "module_index.json": dump(module_index),
        "graph.json": dump(graph),
        "findings.json": dump(findings),
        "evidence.jsonl": "".join(
            json.dumps(e.to_json_dict(), ensure_ascii=False, sort_keys=False) + "\n" for e in evidence
        ),
        ".gitattributes": "# Byte-exact: evidence records cite SHA-256 of these files.\n* -text\n",
        "README.md": (
            "# contract_m1 — SYNTHETIC contract fixture\n\n"
            "Controlled test input from project.md §9.3/§28. Package names are fixture names; this is\n"
            "**not** a scan of any real repository. Regenerate with\n"
            "`python tests/c_contracts/build_contract_fixture.py`; validate with\n"
            "`python -m guardian.cli validate-run tests/fixtures/contract_m1`.\n"
        ),
    }


def main(argv: list[str]) -> int:
    files = build()
    check = "--check" in argv
    drift = []
    for rel, content in files.items():
        path = FIXTURE / rel
        if check:
            if not path.exists() or path.read_bytes() != content.encode("utf-8"):
                drift.append(rel)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode("utf-8"))
    if drift:
        print("fixture drift:", ", ".join(drift))
        return 1
    print("contract_m1 fixture", "matches" if check else "written", f"({len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
