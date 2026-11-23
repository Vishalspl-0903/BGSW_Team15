"""Role E non-CVE detectors (PROJECT.md 6.7 and 9.4).

Implemented now:  D5 GitHub Actions workflow policy.
Not yet:          D1 lockfile baseline diff (reported as NOT_RUN, never as "no changes").
"""

from __future__ import annotations

from typing import Any

from guardian.detectors.d5_ci import scan_workflows

__all__ = ["detect_suspicious_changes", "run_detectors"]


def run_detectors(scan_id: str, repo_dir: str, baseline_ref: str | None, run_dir: str) -> dict[str, Any]:
    """Run every available detector; returns ``{"findings", "evidence", "stages"}``."""
    d5 = scan_workflows(scan_id, repo_dir, run_dir)
    d1_reason = ("no baseline ref supplied; change detection needs a baseline" if not baseline_ref
                 else "D1 lockfile baseline diff is not implemented yet")
    d1_stage = {"stage": "lockfile_change_detection", "status": "NOT_RUN", "attempted": False,
                "tool": "guardian-d1-lockfile", "tool_version": None, "reason": d1_reason,
                "known_matches": None, "completed_at": None, "evidence_ids": []}
    return {"findings": list(d5["findings"]), "evidence": list(d5["evidence"]), "stages": [d5["stage"], d1_stage]}


def detect_suspicious_changes(scan_id: str, repo_dir: str, baseline_ref: str | None, run_dir: str) -> list[Any]:
    """Public contract (PROJECT.md 9.4).  Use ``run_detectors`` for stage records and evidence."""
    return run_detectors(scan_id, repo_dir, baseline_ref, run_dir)["findings"]
