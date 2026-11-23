"""Append-only evidence records and raw-artifact preservation (Role B).

Records follow project.md §9.2 ``Evidence``. IDs are deterministic
(sha256, never ``hash()``) so repeated runs yield identical IDs.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
_ABS_WIN = re.compile(r"[A-Za-z]:[\\/][^\s\"']+")
_ABS_POSIX = re.compile(r"(?<![\w.])/(?:home|Users|tmp|var|mnt)/[^\s\"']+")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def stable_id(prefix: str, *parts: str, length: int = 24) -> str:
    """Deterministic ID over canonical, separator-joined UTF-8 parts."""
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return f"{prefix}:{digest[:length]}"


def scrub_host_paths(text: str) -> str:
    """Remove absolute host paths from text destined for evidence/logs."""
    return _ABS_POSIX.sub("<host-path>", _ABS_WIN.sub("<host-path>", text))


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class EvidenceStore:
    """Collects evidence records; persists them to ``evidence.jsonl``.

    ``run_dir=None`` keeps records in memory only (tests, dry runs).
    """

    def __init__(self, scan_id: str, run_dir: str | Path | None = None) -> None:
        self.scan_id = scan_id
        self.run_dir = Path(run_dir) if run_dir else None
        self.records: dict[str, dict[str, Any]] = {}
        self.errors: list[str] = []

    def add(
        self,
        kind: str,
        observation: str,
        *,
        source_path: str | None = None,
        json_pointer: str | None = None,
        observed_value: Any = None,
        raw_artifact: str | None = None,
        raw_sha256: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
        line_start: int | None = None,
        line_end: int | None = None,
    ) -> str:
        evidence_id = stable_id(
            "ev", self.scan_id, kind, source_path or "", json_pointer or "",
            raw_artifact or "", observation,
        )
        if evidence_id not in self.records:
            self.records[evidence_id] = {
                "schema_version": SCHEMA_VERSION,
                "scan_id": self.scan_id,
                "evidence_id": evidence_id,
                "kind": kind,
                "tool_name": tool_name,
                "tool_version": tool_version,
                "source_path": source_path,
                "json_pointer": json_pointer,
                "line_start": line_start,
                "line_end": line_end,
                "observed_value": observed_value,
                "raw_artifact": raw_artifact,
                "raw_sha256": raw_sha256,
                "observation": observation,
                "recorded_at": utc_now(),
            }
        return evidence_id

    def save_raw(self, name: str, data: bytes, subdir: str = "raw") -> tuple[str | None, str]:
        """Persist bytes under ``<run>/<subdir>/<name>`` (subdir: raw|sbom); return (relpath, sha256)."""
        if subdir not in ("raw", "sbom"):
            raise ValueError("subdir must be 'raw' or 'sbom'")
        digest = sha256_bytes(data)
        if self.run_dir is None:
            return None, digest
        safe = Path(name).name  # no traversal out of the subdir
        target = self.run_dir / subdir / safe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return f"{subdir}/{safe}", digest

    def flush(self) -> Path | None:
        """Append new records to ``evidence.jsonl``; never rewrite or truncate it.

        Records whose ``evidence_id`` is already in the file are skipped (IDs are
        deterministic). If the stored record differs in content (``recorded_at``
        aside) the stored one is kept and the conflict is added to ``self.errors``.
        All new lines are serialised before the file is opened, so a
        serialisation failure writes nothing.
        """
        if self.run_dir is None:
            return None
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / "evidence.jsonl"
        existing: dict[str, dict[str, Any]] = {}
        ends_with_newline = True
        if path.exists():
            data = path.read_bytes()
            ends_with_newline = not data or data.endswith(b"\n")
            for n, line in enumerate(data.splitlines(), 1):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    existing[rec["evidence_id"]] = rec
                except (ValueError, KeyError, TypeError):
                    self.errors.append(f"evidence.jsonl line {n} is unreadable; left untouched")
        lines: list[str] = []
        for eid, rec in self.records.items():
            if eid in existing:
                old = {k: v for k, v in existing[eid].items() if k != "recorded_at"}
                new = json.loads(json.dumps({k: v for k, v in rec.items() if k != "recorded_at"}, ensure_ascii=False))
                if new != old:
                    self.errors.append(f"{eid}: record differs from the stored one; stored record kept")
                continue
            lines.append(json.dumps(rec, sort_keys=True, ensure_ascii=False) + "\n")
        if lines:
            payload = ("" if ends_with_newline else "\n") + "".join(lines)
            with open(path, "a", encoding="utf-8", newline="\n") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
        elif not path.exists():
            path.touch()
        return path

    def index(self) -> dict[str, dict[str, Any]]:
        return dict(self.records)


def load_evidence(path: str | Path) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                rec = json.loads(line)
                out[rec["evidence_id"]] = rec
    return out
