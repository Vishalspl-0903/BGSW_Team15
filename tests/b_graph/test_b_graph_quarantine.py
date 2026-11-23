"""Outside-repository lockfile paths are quarantined: module FAILED, path never written (§7.4, §20)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from b_helpers import comp_by_name, mod, write_project
from guardian.analysis.graph_build import OUTSIDE_PLACEHOLDER, build_and_write
from guardian.evidence import load_evidence

MARK = "leakmarker"
GOOD_LOCK = {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}}


def bad_paths(tmp_path: Path) -> dict[str, str]:
    return {
        "dotdot": f"../{MARK}/package-lock.json",
        "absolute": (tmp_path / MARK / "package-lock.json").as_posix(),
        "windows": f"C:\\..\\{MARK}\\package-lock.json",
        "unc": f"\\\\{MARK}\\share\\package-lock.json",
    }


def run_case(tmp_path: Path, bad_lock: str):
    repo, run = tmp_path / "repo", tmp_path / "run"
    run.mkdir()
    write_project(repo, {"name": "ok"}, GOOD_LOCK, subdir="ok")
    (repo / "bad").mkdir()
    (repo / "bad" / "package.json").write_text("{}")
    bad = mod("bad", lock=None)
    bad["lockfiles"] = [bad_lock]
    out = build_and_write("s1", str(repo), [mod("ok"), bad], str(run))
    return json.loads(Path(out["graph"]).read_text()), out, run


def assert_structurally_valid(graph, evidence_path):
    ids = {m["module_id"] for m in graph["modules"]} | {c["occurrence_id"] for c in graph["components"]}
    assert all(e["source_id"] in ids and e["target_id"] in ids for e in graph["edges"])
    ev = load_evidence(evidence_path)
    assert all(x in ev for c in graph["components"] for x in c["evidence_ids"])
    assert all(x in ev for e in graph["edges"] for x in e["evidence_ids"])
    assert graph["coverage_summary"]["total_modules"] == len(graph["modules"])


@pytest.mark.parametrize("kind", ["dotdot", "absolute", "windows", "unc"])
def test_outside_repo_lockfile_is_quarantined(tmp_path, kind):
    bad_path = bad_paths(tmp_path)[kind]
    graph, out, run = run_case(tmp_path, bad_path)

    modules = {m["relative_path"]: m for m in graph["modules"]}
    bad = modules["bad"]
    assert bad["coverage"] == "FAILED" and bad["coverage_reason"].strip()
    assert "outside repository" in bad["coverage_reason"] and "quarantined" in bad["coverage_reason"]
    assert bad["lockfiles"] == [OUTSIDE_PLACEHOLDER]
    assert any(w.startswith("LOCKFILE_PATH_OUTSIDE_REPO") for w in graph["warnings"])
    # other module unaffected
    assert modules["ok"]["coverage"] == "RESOLVED" and comp_by_name(graph, "x")
    assert graph["coverage_summary"]["failed_modules"] == 1 and graph["coverage_summary"]["resolved_modules"] == 1
    assert_structurally_valid(graph, out["evidence"])
    # quarantine is itself evidenced, without the path
    assert any("quarantined" in r["observation"] for r in load_evidence(out["evidence"]).values())

    # no part of the bad path appears in ANY written file
    needles = [bad_path, bad_path.replace("\\", "/"), MARK, str(tmp_path / MARK)]
    for f in [p for p in run.rglob("*") if p.is_file()]:
        data = f.read_bytes().decode("utf-8", "ignore")
        for n in needles:
            assert n not in data, f"{n!r} leaked into {f.name}"


def test_outside_repo_in_other_path_fields(tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    run.mkdir()
    write_project(repo, {"name": "ok"}, GOOD_LOCK)
    m = mod()
    m["ci_files"] = [f"../{MARK}/wf.yml", ".github/workflows/ok.yml"]
    m["dockerfiles"] = [f"/{MARK}/Dockerfile"]
    out = build_and_write("s1", str(repo), [m], str(run))
    graph = json.loads(Path(out["graph"]).read_text())
    mm = graph["modules"][0]
    assert mm["ci_files"] == [OUTSIDE_PLACEHOLDER, ".github/workflows/ok.yml"] and mm["dockerfiles"] == [OUTSIDE_PLACEHOLDER]
    assert mm["coverage"] == "RESOLVED"                       # lockfile was fine; graph still built
    assert any(w.startswith("MODULE_PATH_OUTSIDE_REPO") for w in graph["warnings"])
    for f in [p for p in run.rglob("*") if p.is_file()]:
        assert MARK not in f.read_bytes().decode("utf-8", "ignore")


def test_symlink_escape_is_quarantined(tmp_path):
    repo, run = tmp_path / "repo", tmp_path / "run"
    outside = tmp_path / MARK
    run.mkdir()
    outside.mkdir()
    (outside / "real-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}))
    (repo / "bad").mkdir(parents=True)
    (repo / "bad" / "package.json").write_text("{}")
    try:
        os.symlink(outside / "real-lock.json", repo / "bad" / "package-lock.json")
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this machine")
    out = build_and_write("s1", str(repo), [mod("bad")], str(run))
    graph = json.loads(Path(out["graph"]).read_text())
    m = graph["modules"][0]
    assert m["coverage"] == "FAILED" and m["lockfiles"] == [OUTSIDE_PLACEHOLDER] and m["coverage_reason"].strip()
    assert any(w.startswith("LOCKFILE_PATH_OUTSIDE_REPO") for w in graph["warnings"])
    for f in [p for p in run.rglob("*") if p.is_file()]:
        assert MARK not in f.read_bytes().decode("utf-8", "ignore")
    assert_structurally_valid(graph, out["evidence"])
