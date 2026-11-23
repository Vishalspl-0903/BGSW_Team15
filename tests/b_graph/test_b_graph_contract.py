"""§7.7 / §6.5 return-shape contract for B's graph queries (exact key sets and status values)."""

from __future__ import annotations

import pytest

import guardian.analysis.paths as paths
from b_helpers import NESTED_LOCK, NESTED_PKG, comp_by_name, mod, write_project
from guardian.analysis.graph_build import build_graph
from guardian.analysis.graph_store import write_graph_db
from guardian.analysis.paths import (
    IMPACT_KEYS, NEIGHBOR_KEYS, PATH_KEYS, PATH_STATUSES, get_dependency_path, get_neighbors, get_reverse_impact,
)

SPEC_PATH_KEYS = {"scan_id", "module_id", "target_occurrence_id", "status", "node_ids", "edge_ids",
                  "edge_evidence_ids", "truncated"}                                  # project.md §7.7
SPEC_NEIGHBOR_KEYS = {"scan_id", "selected_occurrence_id", "direction", "nodes", "edges", "truncated",
                      "coverage_notice"}                                             # §7.7 / §6.5


@pytest.fixture()
def env(tmp_path):
    lock = dict(NESTED_LOCK)
    lock.update({"node_modules/c1": {"version": "1.0.0", "dependencies": {"c2": "1"}},      # isolated cycle
                 "node_modules/c2": {"version": "1.0.0", "dependencies": {"c1": "1"}},
                 "node_modules/orphan": {"version": "1.0.0"}})                            # no parent
    write_project(tmp_path, NESTED_PKG, lock)
    graph = build_graph("s1", str(tmp_path), [mod()], use_syft=False)
    graph = graph if isinstance(graph, dict) else graph.model_dump(mode="json")
    db = str(tmp_path / "g.sqlite")
    write_graph_db(graph, db)
    return db, graph


def oid(graph, name, version=None):
    return comp_by_name(graph, name, version)[0]["occurrence_id"]


def test_path_key_set_is_exactly_the_spec(env):
    db, graph = env
    assert set(PATH_KEYS) == SPEC_PATH_KEYS
    for target in (oid(graph, "deep"), oid(graph, "c1"), oid(graph, "orphan"), "occ:missing"):
        r = get_dependency_path(db, "s1", "mod:.", target)
        assert set(r) == SPEC_PATH_KEYS and r["status"] in PATH_STATUSES
        assert r["scan_id"] == "s1" and r["module_id"] == "mod:." and r["target_occurrence_id"] == target
        assert "path_status" not in r and "path_node_ids" not in r and r["status"] != "OK"


def test_status_values_set_is_exactly_the_spec():
    assert set(PATH_STATUSES) == {"FOUND", "NO_KNOWN_PATH", "UNRESOLVED", "TRUNCATED", "NOT_FOUND"}


def test_found(env):
    db, graph = env
    r = get_dependency_path(db, "s1", "mod:.", oid(graph, "deep"))
    assert r["status"] == "FOUND" and r["truncated"] is False
    assert r["node_ids"][0] == "mod:." and r["node_ids"][-1] == oid(graph, "deep")
    assert len(r["edge_ids"]) == len(r["node_ids"]) - 1 and r["edge_evidence_ids"]
    edge_by_id = {e["edge_id"]: e for e in graph["edges"]}
    for eid, src, dst in zip(r["edge_ids"], r["node_ids"], r["node_ids"][1:]):   # real edge IDs, in order
        assert (edge_by_id[eid]["source_id"], edge_by_id[eid]["target_id"]) == (src, dst)


def test_no_known_path(env):
    db, graph = env
    r = get_dependency_path(db, "s1", "mod:.", oid(graph, "c1"))
    assert r["status"] == "NO_KNOWN_PATH" and r["node_ids"] == [] and r["edge_ids"] == []


def test_unresolved(env):
    db, graph = env
    r = get_dependency_path(db, "s1", "mod:.", oid(graph, "orphan"))
    assert r["status"] == "UNRESOLVED" and r["node_ids"] == []


def test_truncated(env, monkeypatch):
    db, graph = env
    monkeypatch.setattr(paths, "MAX_VISITED", 1)
    r = get_dependency_path(db, "s1", "mod:.", oid(graph, "deep"))
    assert r["status"] == "TRUNCATED" and r["truncated"] is True and r["node_ids"] == []


def test_not_found_unknown_occurrence_module_and_scan(env):
    db, graph = env
    assert get_dependency_path(db, "s1", "mod:.", "occ:x")["status"] == "NOT_FOUND"
    assert get_dependency_path(db, "s1", "mod:nope", oid(graph, "deep"))["status"] == "NOT_FOUND"
    assert get_dependency_path(db, "other-scan", "mod:.", oid(graph, "deep"))["status"] == "NOT_FOUND"


def test_neighbors_shape_and_directions(env):
    db, graph = env
    b = oid(graph, "b")
    for direction, norm in (("dependents", "dependents"), ("in", "dependents"), ("dependencies", "dependencies"),
                            ("out", "dependencies"), ("both", "both")):
        r = get_neighbors(db, "s1", b, direction)
        assert SPEC_NEIGHBOR_KEYS <= set(r) == set(NEIGHBOR_KEYS)
        assert r["direction"] == norm and r["selected_occurrence_id"] == b and r["scan_id"] == "s1"
        assert r["coverage_notice"] == "Graph includes only supported resolved relationships"
        assert all({"id", "type", "label"} <= set(n) for n in r["nodes"])
        assert {n["type"] for n in r["nodes"]} <= {"occurrence", "module"}
    assert {n["label"] for n in get_neighbors(db, "s1", b, "dependencies")["nodes"]} == {"b@1.0.0", "c@2.0.0"}
    assert {n["label"] for n in get_neighbors(db, "s1", b, "dependents")["nodes"]} == {"b@1.0.0", "."}
    assert all({"edge_id", "source_id", "target_id", "evidence_ids"} <= set(e)
               and e["evidence_ids"] for e in get_neighbors(db, "s1", b)["edges"])
    with pytest.raises(ValueError):
        get_neighbors(db, "s1", b, "sideways")


def test_neighbors_status_and_truncation(env):
    db, graph = env
    assert get_neighbors(db, "s1", "occ:nope")["status"] == "NOT_FOUND"
    r = get_neighbors(db, "s1", "mod:.", "dependencies", depth=3, max_nodes=2)
    assert r["status"] == "TRUNCATED" and r["truncated"] is True and len(r["nodes"]) <= 2


def test_reverse_impact_shape_and_paths(env):
    db, graph = env
    deep = oid(graph, "deep")
    r = get_reverse_impact(db, "s1", deep)
    assert set(r) == set(IMPACT_KEYS) and r["status"] == "FOUND" and r["modules"] == ["mod:."]
    chain = r["representative_paths"]["mod:."]
    assert chain[0] == "mod:." and chain[-1] == deep and len(chain) == 4      # root -> b -> c@2 -> deep
    n = get_reverse_impact(db, "s1", oid(graph, "orphan"))
    assert n["status"] == "NO_KNOWN_PATH" and n["modules"] == [] and n["representative_paths"] == {}
    assert get_reverse_impact(db, "s1", "occ:nope")["status"] == "NOT_FOUND"


def test_reverse_impact_truncated_by_module_cap(tmp_path):
    lock = {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}}
    mods = []
    for i in range(3):
        write_project(tmp_path, {"name": f"m{i}"}, lock, subdir=f"m{i}")
        mods.append(mod(f"m{i}"))
    graph = build_graph("s1", str(tmp_path), mods, use_syft=False)
    graph = graph if isinstance(graph, dict) else graph.model_dump(mode="json")
    db = str(tmp_path / "g.sqlite")
    write_graph_db(graph, db)
    x = comp_by_name(graph, "x")[0]["occurrence_id"]
    r = get_reverse_impact(db, "s1", x, max_modules=2)
    assert r["status"] == "TRUNCATED" and r["truncated"] is True and len(r["modules"]) == 2
    assert get_reverse_impact(db, "s1", x)["modules"] == ["mod:m0", "mod:m1", "mod:m2"]
