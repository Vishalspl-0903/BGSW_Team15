"""CycloneDX parsing and Syft dual-format output.

NOTE: every SBOM in this file is hand-made test data. It is NOT real Syft output;
Syft is not installed on this machine, so the subprocess is faked.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import guardian.adapters.syft as syft_mod
from guardian.adapters.syft import parse_cyclonedx, run_syft
from guardian.evidence import EvidenceStore, sha256_bytes

FAKE_CDX = {  # not real Syft output
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "components": [{"bom-ref": "a", "type": "library", "name": "alpha", "version": "1.0.0", "purl": "pkg:npm/alpha@1.0.0"},
                   {"bom-ref": "b", "type": "library", "name": "beta", "version": "2.0.0", "purl": "pkg:npm/beta@2.0.0"}],
    "dependencies": [{"ref": "a", "dependsOn": ["b"]}, {"ref": "b"}],
}
FAKE_SYFT_JSON = {  # not real Syft output
    "artifacts": [{"id": "1", "name": "alpha", "version": "1.0.0", "type": "npm", "purl": "pkg:npm/alpha@1.0.0"},
                  {"id": "2", "name": "beta", "version": "2.0.0", "type": "npm", "purl": "pkg:npm/beta@2.0.0"}]}


def test_cyclonedx_parser_edges_and_flat():
    p = parse_cyclonedx(json.dumps(FAKE_CDX).encode())
    assert [c["name"] for c in p["packages"]] == ["alpha", "beta"] and p["packages"][0]["type"] == "npm"
    assert p["relationship_kind"] == "edges"
    assert p["relationships"] == [{"parent": "a", "child": "b", "type": "depends-on"}]
    flat = dict(FAKE_CDX, dependencies=[{"ref": "a"}])
    assert parse_cyclonedx(json.dumps(flat).encode())["relationship_kind"] == "flat"


@pytest.mark.parametrize("raw", [b"nope", b"[]", b'{"bomFormat": "SPDX"}', b'{"bomFormat":"CycloneDX","components":5}'])
def test_cyclonedx_parser_rejects_malformed(raw):
    with pytest.raises(ValueError):
        parse_cyclonedx(raw)


def _fake_syft(monkeypatch, cdx, stdout: bytes, rc: int = 0):
    monkeypatch.setattr(syft_mod.shutil, "which", lambda _: "syft")
    monkeypatch.setattr(syft_mod, "syft_version", lambda: "0.0-test")
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        for a in argv:
            if isinstance(a, str) and a.startswith("cyclonedx-json=") and cdx is not None:
                Path(a.split("=", 1)[1]).write_bytes(cdx)
        return subprocess.CompletedProcess(argv, rc, stdout, b"")
    monkeypatch.setattr(syft_mod.subprocess, "run", fake_run)
    return calls


def test_run_syft_writes_both_formats_with_hashes(tmp_path, monkeypatch):
    cdx = json.dumps(FAKE_CDX).encode()
    out = json.dumps(FAKE_SYFT_JSON).encode()
    calls = _fake_syft(monkeypatch, cdx, out)
    store = EvidenceStore("s", tmp_path / "run")
    r = run_syft(tmp_path, store)
    assert any(a.startswith("cyclonedx-json=") for a in calls[0]) and "syft-json" in calls[0]   # one run, two formats
    assert r["status"] == "COMPLETE" and r["cdx_components"] == 2
    assert r["sbom_artifact"] == "sbom/syft.cdx.json" and r["raw_artifact"] == "raw/syft.json"
    assert (tmp_path / "run" / "sbom" / "syft.cdx.json").read_bytes() == cdx
    assert (tmp_path / "run" / "raw" / "syft.json").read_bytes() == out
    assert r["sbom_sha256"] == sha256_bytes(cdx) and r["raw_sha256"] == sha256_bytes(out)
    kinds = {(e["kind"], e["raw_artifact"]): e["raw_sha256"] for e in store.records.values()}
    assert kinds[("SBOM", "sbom/syft.cdx.json")] == sha256_bytes(cdx)
    assert kinds[("SBOM", "raw/syft.json")] == sha256_bytes(out)
    assert not any(str(tmp_path) in e["observation"] for e in store.records.values())   # no host paths


def test_run_syft_invalid_cdx_is_flagged_not_hidden(tmp_path, monkeypatch):
    _fake_syft(monkeypatch, b"{ broken", json.dumps(FAKE_SYFT_JSON).encode())
    r = run_syft(tmp_path, EvidenceStore("s", tmp_path / "run"))
    assert r["status"] == "COMPLETE" and "CycloneDX" in r["cdx_warning"]
    assert (tmp_path / "run" / "sbom" / "syft.cdx.json").read_bytes() == b"{ broken"   # raw kept


def test_run_syft_failure_and_missing_cdx(tmp_path, monkeypatch):
    _fake_syft(monkeypatch, None, b"", rc=2)
    assert run_syft(tmp_path, EvidenceStore("s"))["status"] == "FAILED"
    _fake_syft(monkeypatch, None, json.dumps(FAKE_SYFT_JSON).encode())
    r = run_syft(tmp_path, EvidenceStore("s"))
    assert r["status"] == "COMPLETE" and r["sbom_artifact"] is None and "no CycloneDX" in r["cdx_warning"]


def test_syft_missing_keeps_not_run(tmp_path, monkeypatch):
    monkeypatch.setattr(syft_mod.shutil, "which", lambda _: None)
    r = run_syft(tmp_path, EvidenceStore("s", tmp_path / "run"))
    assert r["status"] == "NOT_RUN" and not (tmp_path / "run" / "sbom").exists()


def test_save_raw_subdir_whitelist(tmp_path):
    s = EvidenceStore("s", tmp_path)
    assert s.save_raw("x.json", b"1", subdir="sbom")[0] == "sbom/x.json"
    with pytest.raises(ValueError):
        s.save_raw("x.json", b"1", subdir="../etc")
