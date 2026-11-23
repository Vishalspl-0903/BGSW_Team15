from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from collections import deque
from pathlib import Path

import pytest

import guardian.analysis.paths as paths
from b_helpers import NESTED_LOCK, NESTED_PKG, comp_by_name, edge_pairs, mod, write_project
from guardian.analysis.graph_build import build_graph, build_graph_with_evidence
from guardian.analysis.graph_store import write_graph_db
from guardian.analysis.paths import get_dependency_path, get_neighbors, get_reverse_impact

REPO = Path(__file__).resolve().parents[2]


def g(root, modules, scan="s1"):
    graph = build_graph(scan, str(root), modules, use_syft=False)
    return graph if isinstance(graph, dict) else graph.model_dump(mode="json")


def db(tmp_path, graph):
    p = str(tmp_path / "graph.sqlite")
    write_graph_db(graph, p)
    return p


def ident(graph):
    return ([(c["package_key"], c["occurrence_id"], c["source_refs"]) for c in graph["components"]],
            [(e["edge_id"], e["source_id"], e["target_id"]) for e in graph["edges"]])


# ---- identity / determinism ----------------------------------------------

def test_ids_identical_for_windows_and_posix_separators(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK, subdir="sub")
    posix = mod("sub")
    win = mod("sub")
    win["relative_path"] = "sub"
    win["lockfiles"] = ["sub\\package-lock.json"]
    win["manifests"] = ["sub\\package.json"]
    a, b = g(tmp_path, [posix]), g(tmp_path, [win])
    assert ident(a) == ident(b)
    assert all("\\" not in r for c in b["components"] for r in c["source_refs"])
    assert b["modules"][0]["lockfiles"] == ["sub/package-lock.json"]


def test_ids_repeatable_across_processes_and_hash_seeds(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK)
    code = (
        "import sys,json;sys.path.insert(0,sys.argv[2]);from b_helpers import mod;"
        "from guardian.analysis.graph_build import build_graph;"
        "g=build_graph('s1',sys.argv[1],[mod()],use_syft=False);g=g if isinstance(g,dict) else g.model_dump(mode='json');"
        "print(json.dumps([[c['occurrence_id'] for c in g['components']],[e['edge_id'] for e in g['edges']]]))"
    )
    outs = []
    for seed in ("1", "424242"):
        env = {**os.environ, "PYTHONHASHSEED": seed, "PYTHONPATH": str(REPO)}
        r = subprocess.run([sys.executable, "-c", code, str(tmp_path), str(Path(__file__).parent)],
                           capture_output=True, text=True, env=env, check=True)
        outs.append(r.stdout.strip())
    assert outs[0] == outs[1]
    here = g(tmp_path, [mod()])
    assert json.loads(outs[0]) == [[c["occurrence_id"] for c in here["components"]], [e["edge_id"] for e in here["edges"]]]


# ---- npm dependency kinds -------------------------------------------------

def test_peer_optional_devoptional_bundled_install_script_preserved(tmp_path):
    lock = {
        "": {"dependencies": {"host": "1.0.0", "bund": "1.0.0"}, "optionalDependencies": {"fsevents": "2.0.0"},
             "devDependencies": {"dopt": "1.0.0"}},
        "node_modules/host": {"version": "1.0.0", "peerDependencies": {"plug": "^1"},
                              "peerDependenciesMeta": {"opt-peer": {"optional": True}},
                              "hasInstallScript": True},
        "node_modules/plug": {"version": "1.2.0", "peer": True},
        "node_modules/fsevents": {"version": "2.0.0", "optional": True, "os": ["darwin"], "cpu": ["arm64"]},
        "node_modules/dopt": {"version": "1.0.0", "devOptional": True},
        "node_modules/bund": {"version": "1.0.0", "bundleDependencies": ["inner"], "dependencies": {"inner": "1.0.0"}},
        "node_modules/bund/node_modules/inner": {"version": "1.0.0", "inBundle": True},
    }
    write_project(tmp_path, {"name": "r"}, lock)
    graph, store = build_graph_with_evidence("s1", str(tmp_path), [mod()], use_syft=False)
    pairs = edge_pairs(graph)
    assert {("host@1.0.0", "plug@1.2.0"), ("<root>", "fsevents@2.0.0"), ("bund@1.0.0", "inner@1.0.0")} <= pairs
    raw_graph = graph.model_dump(mode="json") if hasattr(graph, "model_dump") else graph
    edge_scope = {(e["source_id"], e["target_id"]): e["dependency_scope"] for e in raw_graph["edges"]}
    host = comp_by_name(graph, "host")[0]
    plug = comp_by_name(graph, "plug")[0]
    assert edge_scope[(host["occurrence_id"], plug["occurrence_id"])] == "peer"
    assert comp_by_name(graph, "fsevents")[0]["dependency_scopes"] == ["optional"]
    assert comp_by_name(graph, "dopt")[0]["dependency_scopes"] == ["development"]
    assert host["install_stage_indicator"] == "HAS_INSTALL_SCRIPT"
    assert comp_by_name(graph, "inner")[0]["directness"] == "TRANSITIVE"
    assert not any("opt-peer" in w for w in raw_graph["warnings"])          # absent optional peer is not a gap
    # platform facts are preserved in evidence, not silently dropped
    fs_ev = store.records[comp_by_name(graph, "fsevents")[0]["evidence_ids"][0]]["observed_value"]
    assert fs_ev["os"] == ["darwin"] and fs_ev["cpu"] == ["arm64"] and fs_ev["optional"] is True
    assert store.records[comp_by_name(graph, "inner")[0]["evidence_ids"][0]]["observed_value"]["inBundle"] is True


def test_optional_absent_on_this_platform_creates_no_edge_or_warning(tmp_path):
    lock = {"": {"optionalDependencies": {"fsevents": "2.0.0"}}}          # not installed on this platform
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    assert graph["edges"] == [] and graph["warnings"] == []
    assert graph["modules"][0]["coverage"] == "RESOLVED"


def test_two_modules_same_package_two_occurrences_one_key(tmp_path):
    lock = {"": {"dependencies": {"x": "1.0.0"}}, "node_modules/x": {"version": "1.0.0"}}
    for d in ("m1", "m2"):
        write_project(tmp_path, {"name": d}, lock, subdir=d)
    graph = g(tmp_path, [mod("m1"), mod("m2")])
    xs = comp_by_name(graph, "x")
    assert len(xs) == 2 and len({c["occurrence_id"] for c in xs}) == 2
    assert {c["package_key"] for c in xs} == {"npm:x@1.0.0"}


# ---- ambiguity: never a guessed edge --------------------------------------

def test_ambiguous_candidates_no_edge(tmp_path):
    lock = {
        "": {"dependencies": {"a": "1.0.0"}},
        "node_modules/a": {"version": "1.0.0", "dependencies": {"x": "1.0.0"}},
        "node_modules/a/node_modules/x": {"version": "3.0.0"},     # nearest, violates exact 1.0.0
        "node_modules/x": {"version": "1.0.0"},                    # farther, would match
    }
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    assert edge_pairs(graph) == {("<root>", "a@1.0.0")}            # neither candidate was picked
    assert any("AMBIGUOUS_CANDIDATES" in w and "x@1.0.0" in w for w in graph["warnings"])
    assert graph["modules"][0]["coverage"] == "PARTIAL"
    for c in comp_by_name(graph, "x"):
        assert c["directness"] == "UNRESOLVED"


def test_single_candidate_version_mismatch_no_edge(tmp_path):
    lock = {"": {"dependencies": {"a": "1.0.0"}},
            "node_modules/a": {"version": "2.0.0"}}
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    assert graph["edges"] == [] and any("CANDIDATE_VERSION_MISMATCH" in w for w in graph["warnings"])


# ---- query semantics ------------------------------------------------------

def _chain(tmp_path, n):
    packages = {"": {"dependencies": {"p0": "1"}}}
    for i in range(n):
        e = {"version": "1.0.0"}
        if i + 1 < n:
            e["dependencies"] = {f"p{i + 1}": "1"}
        packages[f"node_modules/p{i}"] = e
    write_project(tmp_path, {"name": "chain"}, packages)
    return g(tmp_path, [mod()])


def test_truncation_flag(tmp_path, monkeypatch):
    graph = _chain(tmp_path, 100)
    d = db(tmp_path, graph)
    monkeypatch.setattr(paths, "MAX_VISITED", 5)
    p = get_dependency_path(d, "s1", "mod:.", comp_by_name(graph, "p99")[0]["occurrence_id"])
    assert p["truncated"] is True and p["status"] == "TRUNCATED" and p["node_ids"] == []


def test_unknown_node_is_not_found(tmp_path):
    graph = _chain(tmp_path, 3)
    d = db(tmp_path, graph)
    p = get_dependency_path(d, "s1", "mod:.", "occ:does-not-exist")
    assert p["status"] == "NOT_FOUND" and p["node_ids"] == []
    assert get_neighbors(d, "s1", "occ:nope")["status"] == "NOT_FOUND"
    assert get_reverse_impact(d, "s1", "occ:nope")["status"] == "NOT_FOUND"


def test_no_known_path_vs_unresolved(tmp_path):
    lock = {"": {"dependencies": {"a": "1"}},
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/c1": {"version": "1.0.0", "dependencies": {"c2": "1"}},   # isolated cycle,
            "node_modules/c2": {"version": "1.0.0", "dependencies": {"c1": "1"}},   # every node has a parent
            "node_modules/orphan": {"version": "1.0.0"}}                              # no parent at all
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    d = db(tmp_path, graph)
    p = get_dependency_path(d, "s1", "mod:.", comp_by_name(graph, "c1")[0]["occurrence_id"])
    assert p["status"] == "NO_KNOWN_PATH"
    assert "unreachable" not in json.dumps(p).lower()
    o = get_dependency_path(d, "s1", "mod:.", comp_by_name(graph, "orphan")[0]["occurrence_id"])
    assert o["status"] == "UNRESOLVED"


def test_cycle_path_and_reverse_terminate(tmp_path):
    lock = {"": {"dependencies": {"a": "1"}},
            "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}}}
    write_project(tmp_path, {"name": "r"}, lock)
    graph = g(tmp_path, [mod()])
    d = db(tmp_path, graph)
    a = comp_by_name(graph, "a")[0]["occurrence_id"]
    assert get_dependency_path(d, "s1", "mod:.", a)["edge_ids"].__len__() == 1
    assert get_reverse_impact(d, "s1", a)["modules"] == ["mod:."]


# ---- failure isolation + raw evidence -------------------------------------

def test_failed_module_keeps_raw_evidence_and_others(tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    write_project(repo, {"name": "ok"}, {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}}, subdir="ok")
    (repo / "bad").mkdir()
    (repo / "bad" / "package.json").write_text("{}")
    bad = b'{"lockfileVersion": 3, "packages": {"": {}, "node_modules/x": [1]}}'
    (repo / "bad" / "package-lock.json").write_bytes(bad)
    (repo / "junk").mkdir()
    (repo / "junk" / "package.json").write_text("{}")
    (repo / "junk" / "package-lock.json").write_bytes(b"{ truncated")
    graph, store = build_graph_with_evidence("s1", str(repo), [mod("ok"), mod("bad"), mod("junk")], str(run), use_syft=False)
    raw_graph = graph.model_dump(mode="json") if hasattr(graph, "model_dump") else graph
    cov = {m["relative_path"]: m["coverage"] for m in raw_graph["modules"]}
    assert cov == {"ok": "RESOLVED", "bad": "FAILED", "junk": "FAILED"}
    assert comp_by_name(graph, "x") and raw_graph["coverage_summary"]["failed_modules"] == 2
    raws = sorted(p.name for p in (run / "raw").glob("lockfile-failed-*.json"))
    assert len(raws) == 2
    failed = [r for r in store.records.values() if r["observation"].startswith("lockfile could not be parsed")]
    assert len(failed) == 2 and all(r["raw_sha256"] for r in failed)
    assert {(run / r["raw_artifact"]).read_bytes() for r in failed} == {bad, b"{ truncated"}


# ---- performance: old vs new equivalence ----------------------------------

def _reference_path(db_path, scan_id, module_id, occurrence_id):
    """Original per-node-SQL implementation, kept as the behavioural reference."""
    con = paths._connect(db_path)
    try:
        prev, seen = {}, {occurrence_id}
        queue, parentless, found = deque([occurrence_id]), False, occurrence_id == module_id
        while queue and not found:
            cur = queue.popleft()
            rows = con.execute(f"SELECT edge_id,source FROM edge WHERE scan_id=? AND target=? AND {paths._RESOLVED} ORDER BY edge_id",
                               (scan_id, cur)).fetchall()
            if not rows and cur != module_id:
                parentless = parentless or not con.execute(
                    "SELECT 1 FROM module WHERE scan_id=? AND module_id=?", (scan_id, cur)).fetchone()
            for r in rows:
                if r["source"] in seen:
                    continue
                seen.add(r["source"])
                prev[r["source"]] = (cur, r["edge_id"])
                if r["source"] == module_id:
                    found = True
                    break
                queue.append(r["source"])
        if not found:
            return "UNRESOLVED" if parentless else "NO_KNOWN_PATH", [], []
        nodes, eids, cur = [module_id], [], module_id
        while cur != occurrence_id:
            cur, e = prev[cur]
            nodes.append(cur)
            eids.append(e)
        return "FOUND", nodes, eids
    finally:
        con.close()


def _assert_same(d, graph):
    raw_graph = graph.model_dump(mode="json") if hasattr(graph, "model_dump") else graph
    for m in raw_graph["modules"]:
        for c in raw_graph["components"]:
            new = get_dependency_path(d, "s1", m["module_id"], c["occurrence_id"])
            old = _reference_path(d, "s1", m["module_id"], c["occurrence_id"])
            assert (new["status"], new["node_ids"], new["edge_ids"]) == old


def test_new_path_matches_reference_on_fixtures(tmp_path):
    write_project(tmp_path, NESTED_PKG, NESTED_LOCK)
    graph = g(tmp_path, [mod()])
    _assert_same(db(tmp_path, graph), graph)
    t2 = tmp_path / "t2"
    t2.mkdir()
    lock = {"": {"dependencies": {"a": "1"}}, "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
            "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
            "node_modules/c1": {"version": "1.0.0", "dependencies": {"c2": "1"}},
            "node_modules/c2": {"version": "1.0.0", "dependencies": {"c1": "1"}},
            "node_modules/orphan": {"version": "1.0.0"}}
    write_project(t2, {"name": "r"}, lock)
    graph2 = g(t2, [mod()])
    _assert_same(db(t2, graph2), graph2)


def test_new_path_matches_reference_on_synthetic_dag(tmp_path):
    packages = {"": {"dependencies": {"n0": "1", "n1": "1"}}}
    n = 300
    for i in range(n):                                   # layered DAG with multiple parents per node
        deps = {f"n{j}": "1" for j in (2 * i + 2, 2 * i + 3, i + 5) if j < n and j > i}
        packages[f"node_modules/n{i}"] = {"version": "1.0.0", **({"dependencies": deps} if deps else {})}
    write_project(tmp_path, {"name": "dag"}, packages)
    graph = g(tmp_path, [mod()])
    _assert_same(db(tmp_path, graph), graph)


@pytest.mark.parametrize("n", [100, 1000, 10000])
def test_path_timing(tmp_path, n):
    graph = _chain(tmp_path, n)
    d = db(tmp_path, graph)
    leaf = comp_by_name(graph, f"p{n - 1}")[0]["occurrence_id"]
    t = time.perf_counter()
    p = get_dependency_path(d, "s1", "mod:.", leaf)
    ms = (time.perf_counter() - t) * 1000
    old_ms = float("nan")
    if n <= 1000:   # per-node-SQL reference is too slow at 10k to run inside the suite
        old_t = time.perf_counter()
        old = _reference_path(d, "s1", "mod:.", leaf)
        old_ms = (time.perf_counter() - old_t) * 1000
        assert old[1] == p["node_ids"]
    print(f"\nPATH n={n}: new={ms:.1f}ms reference={old_ms:.1f}ms")
    assert p["status"] == "FOUND" and len(p["edge_ids"]) == n and len(p["node_ids"]) == n + 1
    assert ms < 2000
