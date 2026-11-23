from __future__ import annotations

import json
import subprocess
import sys

import pytest

from guardian.adapters.syft import parse_syft_json, run_syft
from guardian.evidence import EvidenceStore, load_evidence, scrub_host_paths, sha256_bytes, stable_id


def test_evidence_ids_repeatable_across_processes():
    code = "from guardian.evidence import stable_id;print(stable_id('ev','s','LOCKFILE','a','/p'))"
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True).stdout.strip()
            for _ in range(2)}
    assert outs == {stable_id("ev", "s", "LOCKFILE", "a", "/p")}


def test_store_persists_and_hashes_raw(tmp_path):
    s = EvidenceStore("scan1", tmp_path)
    rel, sha = s.save_raw("syft.json", b'{"a":1}')
    eid = s.add("SBOM", "obs", raw_artifact=rel, raw_sha256=sha, tool_name="syft")
    s.add("SBOM", "obs", raw_artifact=rel, raw_sha256=sha, tool_name="syft")   # dedupe
    path = s.flush()
    recs = load_evidence(path)
    assert list(recs) == [eid] and recs[eid]["raw_sha256"] == sha256_bytes((tmp_path / rel).read_bytes())


def test_raw_name_cannot_escape_run_dir(tmp_path):
    s = EvidenceStore("s", tmp_path / "run")
    rel, _ = s.save_raw("../../evil.json", b"x")
    assert rel == "raw/evil.json" and not (tmp_path / "evil.json").exists()


def test_scrub_host_paths():
    assert "Users" not in scrub_host_paths(r"error at C:\Users\Acer\proj\x.js and /home/bob/y")


def test_syft_parser_flat_vs_edges():
    flat = parse_syft_json(json.dumps({"artifacts": [{"id": "1", "name": "a", "version": "1", "type": "npm"}]}).encode())
    assert flat["relationship_kind"] == "flat"
    doc = {"artifacts": [{"id": "1", "name": "a"}, {"id": "2", "name": "b"}],
           "artifactRelationships": [{"parent": "2", "child": "1", "type": "dependency-of"}]}
    assert parse_syft_json(json.dumps(doc).encode())["relationship_kind"] == "edges"


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"artifacts": 5}'])
def test_syft_parser_rejects_malformed(raw):
    with pytest.raises(ValueError):
        parse_syft_json(raw)


def test_syft_absent_is_not_run(tmp_path, monkeypatch):
    import guardian.adapters.syft as s
    monkeypatch.setattr(s.shutil, "which", lambda _: None)
    r = run_syft(tmp_path, EvidenceStore("s"))
    assert r["status"] == "NOT_RUN" and r["tool_version"] is None
