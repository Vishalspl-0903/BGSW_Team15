"""evidence.jsonl is append-only (project.md §9.2)."""

from __future__ import annotations

import json

import pytest

from guardian.evidence import EvidenceStore


def lines(path):
    return path.read_bytes().splitlines(keepends=True)


def test_second_write_keeps_earlier_lines_byte_identical_no_duplicates(tmp_path):
    s1 = EvidenceStore("scan", tmp_path)
    s1.add("LOCKFILE", "first", source_path="a.json", json_pointer="/1", observed_value={"k": 1})
    s1.add("LOCKFILE", "second", source_path="a.json", json_pointer="/2")
    path = s1.flush()
    before = lines(path)
    assert len(before) == 2

    s2 = EvidenceStore("scan", tmp_path)                 # a later run: same two records plus one new
    s2.add("LOCKFILE", "first", source_path="a.json", json_pointer="/1", observed_value={"k": 1})
    s2.add("LOCKFILE", "second", source_path="a.json", json_pointer="/2")
    s2.add("LOCKFILE", "third", source_path="a.json", json_pointer="/3")
    s2.flush()
    after = lines(path)
    assert after[:2] == before                           # earlier lines byte-identical (incl. recorded_at)
    assert len(after) == 3
    ids = [json.loads(x)["evidence_id"] for x in after]
    assert len(ids) == len(set(ids)) and s2.errors == []
    s2.flush()                                            # idempotent
    assert lines(path) == after


def test_same_store_flushed_twice_appends_only_new(tmp_path):
    s = EvidenceStore("scan", tmp_path)
    s.add("MANIFEST", "one")
    path = s.flush()
    first = path.read_bytes()
    s.add("MANIFEST", "two")
    s.flush()
    assert path.read_bytes().startswith(first) and len(lines(path)) == 2


def test_conflicting_record_is_error_and_not_overwritten(tmp_path):
    s1 = EvidenceStore("scan", tmp_path)
    eid = s1.add("LOCKFILE", "entry", source_path="a", json_pointer="/p", observed_value={"sha": "AAA"})
    path = s1.flush()
    original = path.read_bytes()
    s2 = EvidenceStore("scan", tmp_path)
    assert s2.add("LOCKFILE", "entry", source_path="a", json_pointer="/p", observed_value={"sha": "BBB"}) == eid
    s2.flush()
    assert path.read_bytes() == original
    assert len(s2.errors) == 1 and eid in s2.errors[0]


def test_failed_write_does_not_truncate(tmp_path):
    s1 = EvidenceStore("scan", tmp_path)
    s1.add("MANIFEST", "keep me")
    path = s1.flush()
    original = path.read_bytes()
    s2 = EvidenceStore("scan", tmp_path)
    s2.add("MANIFEST", "good new record")
    s2.add("MANIFEST", "bad", observed_value={"x": object()})      # not JSON-serialisable
    with pytest.raises(TypeError):
        s2.flush()
    assert path.read_bytes() == original                           # nothing written, nothing truncated


def test_oserror_during_append_keeps_earlier_content(tmp_path, monkeypatch):
    s1 = EvidenceStore("scan", tmp_path)
    s1.add("MANIFEST", "keep me")
    path = s1.flush()
    original = path.read_bytes()
    s2 = EvidenceStore("scan", tmp_path)
    s2.add("MANIFEST", "new")
    import guardian.evidence as ev
    monkeypatch.setattr(ev.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError):
        s2.flush()
    assert path.read_bytes().startswith(original)                  # append mode: earlier bytes untouched


def test_missing_trailing_newline_and_unreadable_line_are_preserved(tmp_path):
    path = tmp_path / "evidence.jsonl"
    path.write_bytes(b"{not json")                                 # crashed partial write, no newline
    s = EvidenceStore("scan", tmp_path)
    s.add("MANIFEST", "after crash")
    s.flush()
    data = path.read_bytes()
    assert data.startswith(b"{not json\n") and len(data.splitlines()) == 2
    assert any("unreadable" in e for e in s.errors)


def test_empty_store_creates_no_rewrite(tmp_path):
    s = EvidenceStore("scan", tmp_path)
    s.add("MANIFEST", "x")
    path = s.flush()
    mtime_bytes = path.read_bytes()
    EvidenceStore("scan", tmp_path).flush()                        # nothing to add
    assert path.read_bytes() == mtime_bytes


def test_graph_build_twice_into_same_run_dir_is_append_only(tmp_path):
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parents[1] / "b_graph"))
    from b_helpers import mod, write_project
    from guardian.analysis.graph_build import build_graph
    repo, run = tmp_path / "repo", tmp_path / "run"
    write_project(repo, {"name": "r"}, {"": {"dependencies": {"x": "1"}}, "node_modules/x": {"version": "1.0.0"}})
    build_graph("s1", str(repo), [mod()], str(run), use_syft=False)
    first = (run / "evidence.jsonl").read_bytes()
    g = build_graph("s1", str(repo), [mod()], str(run), use_syft=False)
    g = g if isinstance(g, dict) else g.model_dump(mode="json")
    assert (run / "evidence.jsonl").read_bytes() == first
    assert not any(w.startswith("EVIDENCE_CONFLICT") for w in g["warnings"])
