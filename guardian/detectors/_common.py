"""Shared helpers for Role E detectors (no schema definitions live here)."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
_SOURCE_KIND_TO_FIRST_SEEN = {"GIT_PUBLIC": "REAL_UPSTREAM", "CACHED_SNAPSHOT": "REAL_UPSTREAM",
                              "LOCAL_FIXTURE": "LOCAL_FIXTURE"}


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_id(prefix: str, *parts: Any) -> str:
    canonical = json.dumps(list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]}"


def first_seen_in(run_dir: Path | None) -> str:
    """Provenance from C's metadata.json; unknown provenance is never labelled as real upstream."""
    if run_dir is not None and (run_dir / "metadata.json").is_file():
        try:
            kind = json.loads((run_dir / "metadata.json").read_text(encoding="utf-8")).get("source_kind")
            return _SOURCE_KIND_TO_FIRST_SEEN.get(kind, "LOCAL_FIXTURE")
        except (OSError, ValueError):
            pass
    return "LOCAL_FIXTURE"


def module_ids_for(run_dir: Path | None, relative_file: str) -> list[str]:
    """Modules (from A's module_index.json) whose ci_files list contains the file."""
    if run_dir is None or not (run_dir / "module_index.json").is_file():
        return []
    try:
        index = json.loads((run_dir / "module_index.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return sorted(m.get("module_id") for m in index.get("modules") or []
                  if relative_file in (m.get("ci_files") or []) and m.get("module_id"))


def validate(model_name: str, payload: dict[str, Any]) -> Any:
    try:
        from guardian import schemas  # type: ignore[attr-defined]
    except (ImportError, ModuleNotFoundError):
        return payload
    model = getattr(schemas, model_name, None)
    return payload if model is None else model.model_validate(payload)
