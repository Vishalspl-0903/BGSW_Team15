from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import c_fakes
import pytest

from guardian import cli
from guardian.state import validate_run_dir

ROOT = Path(__file__).resolve().parents[2]


def _meta(out: Path) -> dict:
    return json.loads((out / "metadata.json").read_text())


def _states(out: Path) -> list[str]:
    return [json.loads(l)["next_state"] for l in (out / "events.jsonl").read_text().splitlines()]


def test_scan_without_b_and_e_is_honest_partial(tmp_path, monkeypatch, capsys):
    c_fakes.install(monkeypatch, graph=False, vulns=False, detectors=False)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == cli.EXIT_PARTIAL
    meta = _meta(out)
    assert meta["status"] == "PARTIAL"
    assert meta["stage_statuses"]["graph"] == "UNAVAILABLE"
    assert meta["stage_records"]["advisory"]["known_matches"] is None  # unknown, never 0
    assert not (out / "graph.json").exists()  # nothing fabricated
    assert validate_run_dir(out).ok, validate_run_dir(out).errors
    assert cli.main(["findings", "--run", str(out)]) == cli.EXIT_PARTIAL
    assert "UNKNOWN, not zero" in capsys.readouterr().out
    assert cli.main(["graph", "--run", str(out), "--summary"]) == cli.EXIT_UNAVAILABLE


def test_full_scan_with_role_doubles(tmp_path, monkeypatch, capsys):
    c_fakes.install(monkeypatch)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == cli.EXIT_OK
    result = validate_run_dir(out)
    assert result.ok, result.errors
    meta = _meta(out)
    assert meta["status"] == "COMPLETE" and meta["source_kind"] == "LOCAL_FIXTURE"
    assert meta["repo_url"] == "local://fixture/sandbox/sample-app"
    assert _states(out) == ["CREATED", "ACQUIRING", "INDEXING", "INVENTORY_READY", "DETECTING",
                            "FINDINGS_READY", "ANALYZING", "ANALYZED"]
    sids = {json.loads((out / n).read_text())["scan_id"] for n in
            ("metadata.json", "module_index.json", "graph.json", "findings.json", "risk.json")}
    assert sids == {meta["scan_id"]}
    risk = json.loads((out / "risk.json").read_text())
    prios = sorted(a["priority"] for a in risk["assessments"])
    assert prios == ["NEEDS_REVIEW", "P1"]
    assert all(c["validated"] for c in risk["claims"]), risk["claims"]
    capsys.readouterr()
    assert cli.main(["graph", "--run", str(out), "--summary"]) == cli.EXIT_OK
    text = capsys.readouterr().out
    assert "occurrences: 2" in text and "edges: 2" in text
    assert cli.main(["findings", "--run", str(out)]) == cli.EXIT_OK


def test_local_path_outside_allowlist_is_blocked(tmp_path, monkeypatch):
    c_fakes.install(monkeypatch)
    out = tmp_path / "run"
    assert c_fakes.scan(out, src=ROOT / "guardian") == cli.EXIT_BLOCKED
    meta = _meta(out)
    assert meta["status"] == "BLOCKED" and meta["errors"]
    assert not (out / "repo").exists()
    assert validate_run_dir(out).ok


def test_existing_run_is_never_overwritten(tmp_path, monkeypatch):
    c_fakes.install(monkeypatch)
    out = tmp_path / "run"
    out.mkdir()
    (out / "keep.txt").write_text("previous")
    assert c_fakes.scan(out) == cli.EXIT_BLOCKED
    assert sorted(p.name for p in out.iterdir()) == ["keep.txt"]


def test_conflicting_scan_id_from_detector_is_dropped(tmp_path, monkeypatch):
    def bad_vulns(scan_id, graph, run_dir):
        ev = c_fakes._evidence(Path(run_dir), scan_id, "ev:adv", "ADVISORY", "package-lock.json", "x")
        f = c_fakes.advisory_finding(scan_id, graph, ev)
        return [f.model_copy(update={"scan_id": "another-scan"})]

    c_fakes.install(monkeypatch, vuln_fn=bad_vulns)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == cli.EXIT_PARTIAL
    meta = _meta(out)
    assert meta["stage_statuses"]["advisory"] == "PARTIAL"
    assert any("conflicting scan_id" in e for e in meta["errors"])
    assert json.loads((out / "findings.json").read_text())["findings"][0]["classification"] != "CONFIRMED_ADVISORY"
    assert validate_run_dir(out).ok


def test_detector_crash_is_failed_not_zero(tmp_path, monkeypatch):
    class AdvisoryDatabaseUnavailable(RuntimeError):
        pass

    def broken(scan_id, graph, run_dir):
        raise AdvisoryDatabaseUnavailable("grype db missing; token=ghp_abcdefghijklmnopqrstuvwxyz123456")

    c_fakes.install(monkeypatch, vuln_fn=broken)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == cli.EXIT_PARTIAL
    rec = _meta(out)["stage_records"]["advisory"]
    assert rec["status"] == "UNAVAILABLE" and rec["known_matches"] is None and rec["evidence_ids"]
    blob = (out / "metadata.json").read_text() + (out / "raw" / "stage-advisory.log").read_text()
    assert "ghp_abcdefghijklmnopqrstuvwxyz123456" not in blob  # secrets redacted from errors/logs
    assert validate_run_dir(out).ok


def test_graph_with_dangling_edge_is_rejected(tmp_path, monkeypatch):
    def bad_graph(scan_id, repo_dir, modules):
        g = c_fakes.fake_build_graph(scan_id, repo_dir, modules)
        edges = [e.model_copy(update={"target_id": "occ:ghost"}) for e in g.edges]
        return g.model_copy(update={"edges": edges})

    c_fakes.install(monkeypatch, graph_fn=bad_graph)
    out = tmp_path / "run"
    assert c_fakes.scan(out) == cli.EXIT_PARTIAL
    assert _meta(out)["stage_statuses"]["graph"] == "FAILED"
    assert not (out / "graph.json").exists()
    assert _meta(out)["stage_statuses"]["advisory"] == "BLOCKED"
    assert validate_run_dir(out).ok


def test_scan_cli_subprocess_offline_disabled_llm(tmp_path):
    env = {**os.environ, "LLM_MODE": "disabled", "GROQ_API_KEY": "", "HTTPS_PROXY": "http://127.0.0.1:9"}
    out = tmp_path / "run"
    proc = subprocess.run([sys.executable, "-m", "guardian.cli", "scan", "--local", "sandbox/sample-app",
                           "--out", str(out)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode in (cli.EXIT_OK, cli.EXIT_PARTIAL), proc.stdout + proc.stderr
    assert f"run: {out.as_posix()}" in proc.stdout
    v = subprocess.run([sys.executable, "-m", "guardian.cli", "validate-run", str(out)], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=120)
    assert v.returncode == 0, v.stdout


@pytest.mark.parametrize("cmd", [["path", "--run", "x", "--module", "m", "--component", "c"], ["report", "--run", "x"]])
def test_unmerged_roles_report_unavailable(cmd, monkeypatch):
    monkeypatch.setitem(sys.modules, "guardian.analysis.paths", None)
    monkeypatch.setitem(sys.modules, "guardian.reporter", None)
    assert cli.main(cmd) == cli.EXIT_UNAVAILABLE
