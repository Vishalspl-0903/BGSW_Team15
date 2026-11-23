import json
import os

os.makedirs('tests/fixtures/synthetic_10000', exist_ok=True)

metadata = {
    "schema_version": "1.0",
    "scan_id": "scan-synthetic-10000",
    "repo_url": "local://fixture/synthetic-10000",
    "commit_sha": None,
    "source_kind": "LOCAL_FIXTURE",
    "started_at": "2026-11-23T10:00:00Z",
    "finished_at": "2026-11-23T10:00:10Z",
    "status": "COMPLETE",
    "tool_versions": {"benchmarker": "1.0"},
    "errors": [],
    "stage_statuses": {"graph": "COMPLETE"},
    "database_snapshots": {},
    "source_snapshot_sha256": "0" * 64,
    "scope_capabilities": {"scale": "10000_components"}
}

components = []
edges = []
root_id = "mod-synth-root"

# Create 10,000 components
for i in range(10000):
    occ_id = f"occ-pkg-{i:05d}"
    is_direct = (i < 50)
    directness = "DIRECT" if is_direct else "TRANSITIVE"
    parent_id = root_id if is_direct else f"occ-pkg-{(i % 50):05d}"
    
    components.append({
        "package_key": f"npm:synthetic-lib-{i:05d}@1.0.0",
        "ecosystem": "npm",
        "name": f"synthetic-lib-{i:05d}",
        "resolved_version": "1.0.0",
        "declared_constraint": "^1.0.0",
        "purl": f"pkg:npm/synthetic-lib-{i:05d}@1.0.0",
        "occurrence_id": occ_id,
        "module_id": root_id,
        "source_refs": [f"package-lock.json#synthetic-lib-{i:05d}"],
        "resolution": "RESOLVED",
        "evidence_ids": [f"ev-synth-{i:05d}"],
        "install_stage_indicator": None,
        "dependency_scopes": ["production" if i % 2 == 0 else "development"],
        "directness": directness,
        "license": "MIT",
        "artifact_hashes": [],
        "package_source_type": "REGISTRY",
        "resolved_source_url": None,
        "registry_host": "registry.npmjs.org",
        "source_scope": "SOURCE",
        "image_presence": "NOT_CHECKED",
        "manifest_refs": ["package.json"] if is_direct else []
    })

    edges.append({
        "edge_id": f"edge-synth-{i:05d}",
        "source_id": parent_id,
        "target_id": occ_id,
        "relationship": "DEPENDS_ON",
        "evidence_ids": [f"ev-synth-{i:05d}"],
        "module_id": root_id,
        "resolution": "OBSERVED",
        "dependency_scope": "production" if i % 2 == 0 else "development",
        "declared_constraint": "^1.0.0",
        "source_scope": "SOURCE"
    })

graph_bundle = {
    "schema_version": "1.0",
    "scan_id": "scan-synthetic-10000",
    "modules": [
        {
            "module_id": root_id,
            "relative_path": ".",
            "ecosystem": "npm",
            "manifests": ["package.json"],
            "lockfiles": ["package-lock.json"],
            "ci_files": [],
            "dockerfiles": [],
            "coverage": "RESOLVED",
            "coverage_reason": "",
            "scanner_names": ["benchmarker"],
            "file_counts": {"found": 10000, "scanned": 10000, "failed": 0, "unsupported": 0},
            "scan_stage": {"graph": "COMPLETE"},
            "artifact_sbom_status": "NOT_RUN"
        }
    ],
    "components": components,
    "edges": edges,
    "coverage_summary": {
        "total_modules": 1,
        "resolved_modules": 1,
        "partial_modules": 0,
        "declared_only_modules": 0,
        "unsupported_modules": 0,
        "failed_modules": 0
    },
    "warnings": []
}

with open('tests/fixtures/synthetic_10000/metadata.json', 'w', encoding='utf-8') as f:
    json.dump(metadata, f, indent=2)

with open('tests/fixtures/synthetic_10000/graph.json', 'w', encoding='utf-8') as f:
    json.dump(graph_bundle, f)

print('Generated 10,000 component synthetic fixture')

