from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from guardian.analysis.time_machine import ComparisonError, compare_runs


def _component(name: str, version: str, ref: str, *, source_type="REGISTRY", url=None):
    return {"occurrence_id": f"occ:{name}:{version}", "module_id": "mod:root",
            "package_key": f"npm:{name}@{version}", "ecosystem": "npm", "name": name,
            "resolved_version": version, "source_refs": [ref], "directness": "TRANSITIVE",
            "package_source_type": source_type, "resolved_source_url": url,
            "registry_host": "registry.npmjs.org" if source_type == "REGISTRY" else None,
            "artifact_hashes": []}


def _write_run(path: Path, commit: str, components: list[dict], edges: list[dict], findings: list[dict], snapshot="2026-01-01T00:00:00Z"):
    path.mkdir()
    metadata = {"scan_id": path.name, "repo_url": "https://github.com/example/repo", "commit_sha": commit,
                "database_snapshots": {"grype": snapshot} if snapshot else {}}
    graph = {"modules": [{"module_id": "mod:root", "relative_path": "."}],
             "components": components, "edges": edges}
    (path / "metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    (path / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    (path / "findings.json").write_text(json.dumps({"findings": findings}), encoding="utf-8")


def _edge(target: str):
    return {"source_id": "mod:root", "target_id": target, "relationship": "DEPENDS_ON",
            "dependency_scope": "production", "resolution": "OBSERVED"}


def _finding(component: dict, advisory="GHSA-test"):
    return {"classification": "CONFIRMED_ADVISORY", "occurrence_ids": [component["occurrence_id"]],
            "advisory_ids": [advisory], "advisory_aliases": [], "finding_id": f"fnd:{advisory}",
            "title": advisory, "priority": "P1", "module_ids": ["mod:root"], "evidence_ids": ["ev:test"]}


def test_compare_classifies_upgrade_origin_edge_and_new_advisory(tmp_path: Path):
    old = _component("alpha", "1.0.0", "package-lock.json#/packages/node_modules~1alpha")
    new = _component("alpha", "2.0.0", "package-lock.json#/packages/node_modules~1alpha",
                     source_type="GIT", url="https://github.com/example/alpha.git#abc")
    added = _component("helper", "1.0.0", "package-lock.json#/packages/node_modules~1helper")
    _write_run(tmp_path / "base", "a" * 40, [old], [_edge(old["occurrence_id"])], [])
    _write_run(tmp_path / "current", "b" * 40, [new, added],
               [_edge(new["occurrence_id"]), _edge(added["occurrence_id"])], [_finding(added)])

    result = compare_runs(tmp_path / "base", tmp_path / "current")

    assert result["advisory_snapshot"]["code_change_attribution_allowed"] is True
    assert [p["name"] for p in result["changes"]["added_packages"]] == ["helper"]
    assert result["changes"]["removed_packages"] == []
    assert result["changes"]["upgraded_packages"][0]["before_version"] == "1.0.0"
    assert result["changes"]["changed_sources"][0]["after"]["type"] == "GIT"
    assert len(result["changes"]["added_edges"]) == 2
    assert len(result["changes"]["new_advisories"]) == 1
    assert any(path[-1][-1] == "npm:helper@1.0.0" for path in result["changes"]["changed_paths"])


def test_different_advisory_snapshot_blocks_code_attribution(tmp_path: Path):
    item = _component("alpha", "1.0.0", "package-lock.json#/packages/node_modules~1alpha")
    _write_run(tmp_path / "base", "a" * 40, [item], [_edge(item["occurrence_id"])], [], "old")
    _write_run(tmp_path / "current", "b" * 40, [item], [_edge(item["occurrence_id"])], [_finding(item)], "new")
    result = compare_runs(tmp_path / "base", tmp_path / "current")
    assert result["advisory_snapshot"]["status"] == "DIFFERENT"
    assert result["advisory_snapshot"]["code_change_attribution_allowed"] is False
    assert "Not attributable" in result["vulnerability_attribution"]


def test_rejects_different_repositories_and_bad_limit(tmp_path: Path):
    item = _component("alpha", "1", "lock#/alpha")
    _write_run(tmp_path / "base", "a" * 40, [item], [], [])
    _write_run(tmp_path / "current", "b" * 40, [item], [], [])
    metadata = json.loads((tmp_path / "current/metadata.json").read_text(encoding="utf-8"))
    metadata["repo_url"] = "https://github.com/example/other"
    (tmp_path / "current/metadata.json").write_text(json.dumps(metadata), encoding="utf-8")
    with pytest.raises(ComparisonError, match="different repositories"):
        compare_runs(tmp_path / "base", tmp_path / "current")
    with pytest.raises(ComparisonError, match="max_changes"):
        compare_runs(tmp_path / "base", tmp_path / "current", max_changes=0)
