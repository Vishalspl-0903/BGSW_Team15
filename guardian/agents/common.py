"""Shared helpers for agent roles: transcripts as MODEL_OUTPUT evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from guardian.llm import LLMResult
from guardian.schemas import SCHEMA_VERSION, Evidence, stable_id, utc_now
from guardian.state import append_jsonl


def record_transcript(run_dir: str | Path | None, scan_id: str, role: str, subject_id: str,
                      result: LLMResult) -> str | None:
    """Persist a redacted, bounded transcript and a MODEL_OUTPUT evidence record.

    MODEL_OUTPUT evidence exists for audit only; ``guardian.claims`` never lets it
    support a verified claim and validate-run rejects it behind OBSERVED edges.
    """
    if run_dir is None or result.attempts == 0:
        return None
    root = Path(run_dir)
    stamp = utc_now()
    evidence_id = stable_id("ev", scan_id, "model", role, subject_id, stamp)
    rel = f"raw/llm/{evidence_id.replace(':', '_')}.json"
    payload = {
        "role": role, "subject_id": subject_id, "provider": result.provider_label,
        "status": result.status.value, "attempts": result.attempts, "error": result.error,
        "prompt_redacted": result.prompt_redacted, "response_redacted": result.raw_redacted,
    }
    data = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    ev = Evidence(
        schema_version=SCHEMA_VERSION, scan_id=scan_id, evidence_id=evidence_id, kind="MODEL_OUTPUT",
        tool_name=f"guardian-{role.lower()}", tool_version=result.provider_label, source_path=None,
        json_pointer=None, line_start=None, line_end=None, observed_value=result.status.value,
        raw_artifact=rel, raw_sha256=hashlib.sha256(data).hexdigest(),
        observation=f"{role} model call for {subject_id}: {result.status.value} (advisory text, not evidence)",
        recorded_at=stamp,
    )
    append_jsonl(root / "evidence.jsonl", ev.to_json_dict())
    return evidence_id
