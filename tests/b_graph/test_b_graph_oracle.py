"""Consumer + oracle tests: real graph.json vs `npm ls --package-lock-only --all --json`."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from b_helpers import NESTED_LOCK, NESTED_PKG, edge_pairs, mod, write_project
from guardian.adapters.npm import oracle_edge_set, run_npm_ls_oracle
from guardian.analysis.graph_build import build_and_write
from guardian.analysis.paths import get_dependency_path

pytestmark = pytest.mark.skipif(shutil.which("npm") is None, reason="npm not installed")
REPO = Path(__file__).resolve().parents[2]


def _oracle_compare(project: Path, run: Path, modules):
    out = build_and_write("oracle", str(project), modules, str(run))
    graph = json.loads(Path(out["graph"]).read_text())        # load the way E/D will
    oracle = run_npm_ls_oracle(project)
    assert oracle["available"] and oracle["tree"] is not None, oracle.get("stderr")
    return graph, oracle, oracle_edge_set(oracle["tree"])


def test_nested_fixture_matches_npm_ls(tmp_path):
    proj, run = tmp_path / "p", tmp_path / "run"
    run.mkdir()
    write_project(proj, NESTED_PKG, NESTED_LOCK)
    graph, oracle, expected = _oracle_compare(proj, run, [mod()])
    mine = edge_pairs(graph)
    print(f"\nORACLE nested: npm={oracle['npm_version']} exit={oracle['exit_code']} "
          f"npm_edges={len(expected)} guardian_edges={len(mine)}")
    assert mine == expected


def test_sandbox_sample_app_matches_npm_ls(tmp_path):
    src = REPO / "sandbox" / "sample-app"
    proj, run = tmp_path / "p", tmp_path / "run"
    run.mkdir()
    proj.mkdir()
    for f in ("package.json", "package-lock.json"):
        shutil.copy(src / f, proj / f)
    graph, oracle, expected = _oracle_compare(proj, run, [mod()])
    mine = edge_pairs(graph)
    print(f"\nORACLE sample-app: npm={oracle['npm_version']} exit={oracle['exit_code']} "
          f"npm_edges={len(expected)} guardian_edges={len(mine)} edges={sorted(mine)}")
    assert mine == expected and len(mine) == 2


def test_consumer_loads_graph_and_queries_db(tmp_path):
    """E/D-style consumption: only graph.json + graph.sqlite, no lockfile reparsing."""
    proj, run = tmp_path / "p", tmp_path / "run"
    run.mkdir()
    write_project(proj, NESTED_PKG, NESTED_LOCK)
    out = build_and_write("oracle", str(proj), [mod()], str(run))
    graph = json.loads(Path(out["graph"]).read_text())
    deep = next(c for c in graph["components"] if c["name"] == "deep")
    p = get_dependency_path(out["db"], "oracle", graph["modules"][0]["module_id"], deep["occurrence_id"])
    assert p["path_status"] == "FOUND" and p["hops"] == 3     # root -> b -> c@2 -> deep
    assert deep["purl"] == "pkg:npm/deep@1.0.0" and deep["package_key"] == "npm:deep@1.0.0"
