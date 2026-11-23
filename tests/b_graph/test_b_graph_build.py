from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from b_helpers import NESTED_LOCK, NESTED_PKG, comp_by_name, edge_pairs, mod, write_project
from guardian.analysis.graph_build import build_graph, build_and_write
from guardian.analysis.graph_store import write_graph_db
from guardian.analysis.paths import get_dependency_path, get_neighbors, get_reverse_impact


def g(tmp_path, modules, scan="s1"):
    graph = build_graph(scan, str(tmp_path), modules, use_syft=False)
    return graph if isinstance(graph, dict) else graph.model_dump(mode="json")


def db(tmp_path, graph):
    p = str(tmp_path / "graph.sqlite")
    write_graph_db(graph, p)
    return p


def test_hidden_transitive_three_levels(tmp_path):
    write_project(tmp_path, {"name": "r"}, {
        "": {"dependencies": {"web": "1.0.0"}},
        "node_modules/web": {"version": "1.0.0", "dependencies": {"mid": "^1"}},
        "node_modules/mid": {"version": "1.0.0", "dependencies": {"leaf": "^1"}},
        "node_modules/leaf": {"version": "1.0.0"},
    })
    graph = g(tmp_path, [mod()])
    assert edge_pairs(graph) == {("<root>", "web@1.0.0"), ("web@1.0.0", "mid@1.0.0"), ("mid@1.0.0", "leaf@1.0.0")}
    leaf = comp_by_name(graph, "leaf")[0]
    assert leaf["directness"] == "TRANSITIVE" and comp_by_name(graph, "web")[0]["directness"] == "DIRECT"
    p = get_dependency_path(db(tmp_path, graph), "s1", "mod:.", leaf["occurrence_id"])
    assert p["path_status"] == "FOUND" and p["hops"] == 3 and p["path_node_ids"][0] == "mod:."
    assert p["evidence_ids"]


def test_nested_duplicate_versions_and_scoped(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK)
    graph = g(tmp_path, [mod()])
    pairs = edge_pairs(graph)
    assert ("a@1.0.0", "c@1.0.0") in pairs and ("b@1.0.0", "c@2.0.0") in pairs
    assert ("a@1.0.0", "c@2.0.0") not in pairs and ("b@1.0.0", "c@1.0.0") not in pairs
    assert {c["package_key"] for c in comp_by_name(graph, "c")} == {"npm:c@1.0.0", "npm:c@2.0.0"}
    assert comp_by_name(graph, "@sc/s")[0]["purl"] == "pkg:npm/%40sc/s@1.0.0"
    assert comp_by_name(graph, "@sc/s")[0]["install_stage_indicator"] == "HAS_INSTALL_SCRIPT"
    assert comp_by_name(graph, "devtool")[0]["dependency_scopes"] == ["development"]
    c2 = comp_by_name(graph, "c", "2.0.0")[0]
    p = get_dependency_path(db(tmp_path, graph), "s1", "mod:.", c2["occurrence_id"])
    names = {x["occurrence_id"]: x["name"] for x in graph["components"]}
    assert [names.get(n, "root") for n in p["path_node_ids"]] == ["root", "b", "c"]


def test_same_package_two_modules_distinct_occurrences(tmp_path):
    lock = {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}}
    write_project(tmp_path, {"name": "m1"}, lock, subdir="m1")
    write_project(tmp_path, {"name": "m2"}, lock, subdir="m2")
    graph = g(tmp_path, [mod("m1"), mod("m2")])
    xs = comp_by_name(graph, "x")
    assert len(xs) == 2 and len({c["occurrence_id"] for c in xs}) == 2
    assert len({c["package_key"] for c in xs}) == 1
    d = db(tmp_path, graph)
    r = get_reverse_impact(d, "s1", xs[0]["occurrence_id"])
    assert r["modules"] == ["mod:m1", "mod:m2"] and len(r["affected_occurrence_ids"]) == 2


def test_missing_parent_no_invented_edge(tmp_path):
    lock = {"": {"dependencies": {"a": "1"}}, "node_modules/a": {"version": "1.0.0"},
            "node_modules/orphan": {"version": "9.9.9"}}
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    orphan = comp_by_name(graph, "orphan")[0]
    assert orphan["directness"] == "UNRESOLVED"
    assert all(e["target_id"] != orphan["occurrence_id"] for e in graph["edges"])
    assert graph["modules"][0]["coverage"] == "PARTIAL"
    assert any("UNRESOLVED_PARENT" in w for w in graph["warnings"])
    p = get_dependency_path(db(tmp_path, graph), "s1", "mod:.", orphan["occurrence_id"])
    assert p["path_status"] == "UNRESOLVED" and p["path_node_ids"] == []


def test_declaration_without_target_is_not_an_edge(tmp_path):
    lock = {"": {"dependencies": {"a": "1"}}, "node_modules/a": {"version": "1.0.0",
            "dependencies": {"ghost": "^1"}, "optionalDependencies": {"fsevents": "2"}}}
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    assert edge_pairs(graph) == {("<root>", "a@1.0.0")}
    assert any("ghost" in w for w in graph["warnings"])
    assert not any("fsevents" in w for w in graph["warnings"])   # optional absent is not a gap
    assert graph["modules"][0]["coverage"] == "PARTIAL"


def test_cycle_terminates(tmp_path):
    lock = {"": {"dependencies": {"a": "1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}}}
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    d = db(tmp_path, graph)
    b = comp_by_name(graph, "b")[0]
    assert get_dependency_path(d, "s1", "mod:.", b["occurrence_id"])["hops"] == 2
    n = get_neighbors(d, "s1", b["occurrence_id"], "both", depth=10)
    assert len(n["nodes"]) == 3
    assert get_reverse_impact(d, "s1", b["occurrence_id"])["modules"] == ["mod:."]


def test_workspace_links(tmp_path):
    lock = {
        "": {"name": "mono", "workspaces": ["packages/*"], "dependencies": {"wsa": "*"}},
        "node_modules/wsa": {"resolved": "packages/wsa", "link": True},
        "packages/wsa": {"name": "wsa", "version": "1.0.0", "dependencies": {"lib": "^1"}},
        "node_modules/lib": {"version": "1.0.0"},
    }
    write_project(tmp_path, {"name": "mono"}, lock)
    graph = g(tmp_path, [mod()])
    assert edge_pairs(graph) == {("<root>", "wsa@1.0.0"), ("wsa@1.0.0", "lib@1.0.0")}
    assert comp_by_name(graph, "wsa")[0]["package_source_type"] == "WORKSPACE"
    assert len([c for c in graph["components"] if c["name"] == "wsa"]) == 1   # link is not a second node


def test_malformed_lock_fails_only_that_module(tmp_path):
    write_project(tmp_path, {"name": "ok"}, {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}}, subdir="ok")
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "package.json").write_text("{}")
    (tmp_path / "bad" / "package-lock.json").write_text("{ not json")
    graph = g(tmp_path, [mod("ok"), mod("bad")])
    cov = {m["relative_path"]: m["coverage"] for m in graph["modules"]}
    assert cov == {"ok": "RESOLVED", "bad": "FAILED"}
    assert comp_by_name(graph, "x") and graph["coverage_summary"]["failed_modules"] == 1
    assert any("MODULE_FAILED" in w for w in graph["warnings"])


def test_lockfile_v1_not_claimed_resolved(tmp_path):
    write_project(tmp_path, {"name": "r"}, None)
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    graph = g(tmp_path, [mod()])
    assert graph["modules"][0]["coverage"] == "FAILED" and "unsupported" in graph["modules"][0]["coverage_reason"]


def test_no_lockfile_declared_only_no_observed_edges(tmp_path):
    write_project(tmp_path, {"name": "r", "dependencies": {"x": "^1.2.0"}}, None)
    graph = g(tmp_path, [mod(lock=None)])
    c = graph["components"][0]
    assert graph["modules"][0]["coverage"] == "DECLARED_ONLY"
    assert c["package_key"] is None and c["resolved_version"] is None and c["resolution"] == "DECLARED_ONLY"
    assert all(e["resolution"] != "OBSERVED" for e in graph["edges"])


def test_non_npm_module_unsupported_not_clean(tmp_path):
    m = mod("py", lock=None)
    m["ecosystem"] = "pypi"
    graph = g(tmp_path, [m])
    assert graph["modules"][0]["coverage"] == "UNSUPPORTED" and graph["components"] == []


def test_scanner_unavailable_is_reported(tmp_path, monkeypatch):
    import guardian.adapters.syft as s
    monkeypatch.setattr(s.shutil, "which", lambda _: None)
    write_project(tmp_path, {"name": "r"}, {"": {}})
    graph = build_graph("s1", str(tmp_path), [mod()], use_syft=True)
    graph = graph if isinstance(graph, dict) else graph.model_dump(mode="json")
    assert any(w.startswith("SYFT_NOT_RUN") for w in graph["warnings"])


def test_path_escape_lockfile_rejected(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "package-lock.json").write_text("{}")
    repo = tmp_path / "repo"
    repo.mkdir()
    m = mod(lock=None)
    m["lockfiles"] = ["../outside/package-lock.json"]
    graph = g(repo, [m])
    assert graph["modules"][0]["coverage"] == "FAILED"


def test_ids_unique_and_edges_have_evidence(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK)
    graph = g(tmp_path, [mod()])
    ids = [m["module_id"] for m in graph["modules"]] + [c["occurrence_id"] for c in graph["components"]]
    assert len(ids) == len(set(ids)) and len({e["edge_id"] for e in graph["edges"]}) == len(graph["edges"])
    assert all(e["evidence_ids"] for e in graph["edges"] if e["resolution"] == "OBSERVED")
    assert all(e["source_id"] in ids and e["target_id"] in ids for e in graph["edges"])


def test_build_is_deterministic(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK)
    a, b = g(tmp_path, [mod()]), g(tmp_path, [mod()])
    assert [c["occurrence_id"] for c in a["components"]] == [c["occurrence_id"] for c in b["components"]]
    assert [e["edge_id"] for e in a["edges"]] == [e["edge_id"] for e in b["edges"]]


@pytest.mark.parametrize("n", [100, 1000, 10000])
def test_synthetic_scale_bounded(tmp_path, n):
    packages = {"": {"dependencies": {"p0": "1"}}}
    for i in range(n):
        entry = {"version": "1.0.0"}
        if i + 1 < n:
            entry["dependencies"] = {f"p{i + 1}": "1"}        # long chain: worst case for path length
        packages[f"node_modules/p{i}"] = entry
    write_project(tmp_path, {"name": "big"}, packages)
    t = time.perf_counter()
    graph = g(tmp_path, [mod()])
    build_s = time.perf_counter() - t
    d = db(tmp_path, graph)
    leaf = comp_by_name(graph, f"p{n - 1}")[0]["occurrence_id"]
    t = time.perf_counter()
    p = get_dependency_path(d, "s1", "mod:.", leaf)
    nb = get_neighbors(d, "s1", "mod:.", "out", depth=10, max_nodes=150)
    q_ms = (time.perf_counter() - t) * 1000
    assert p["path_status"] == "FOUND" and p["hops"] == n
    assert len(nb["nodes"]) <= 150
    print(f"\nSCALE n={n}: build={build_s:.2f}s path+neighbors={q_ms:.1f}ms")
    assert q_ms < 5000


def test_neighbors_bounded_on_hub(tmp_path):
    packages = {"": {"dependencies": {f"h{i}": "1" for i in range(500)}}}
    packages.update({f"node_modules/h{i}": {"version": "1.0.0"} for i in range(500)})
    write_project(tmp_path, {"name": "hub"}, packages)
    graph = g(tmp_path, [mod()])
    n = get_neighbors(db(tmp_path, graph), "s1", "mod:.", "out", depth=1, max_nodes=50)
    assert len(n["nodes"]) == 50 and n["truncated"] is True


def test_build_and_write_artifacts_roundtrip(tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    run.mkdir()
    write_project(repo, NESTED_PKG, NESTED_LOCK)
    out = build_and_write("s1", str(repo), [mod()], str(run))
    data = json.loads(Path(out["graph"]).read_text())
    ev_ids = {json.loads(l)["evidence_id"] for l in Path(out["evidence"]).read_text().splitlines()}
    assert all(x in ev_ids for e in data["edges"] for x in e["evidence_ids"])
