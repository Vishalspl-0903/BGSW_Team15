"""Syft source-SBOM adapter (Role B). Never fabricates output.

If Syft is absent the result is ``status="NOT_RUN"``; a crash or malformed
output is ``FAILED`` with the raw bytes still preserved and hashed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from guardian.evidence import EvidenceStore, scrub_host_paths


def syft_version() -> str | None:
    exe = shutil.which("syft")
    if exe is None:
        return None
    try:
        res = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return None
    for line in res.stdout.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return res.stdout.strip().splitlines()[0] if res.stdout.strip() else None


def parse_syft_json(raw: bytes) -> dict[str, Any]:
    """Validate structure and extract npm packages plus relationships.

    Respects Syft's own ID namespace (artifact ``id``). ``relationship_kind``
    is ``flat`` when Syft supplied no relationships, else ``edges``.
    """
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"Syft output is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("artifacts"), list):
        raise ValueError("Syft output lacks an 'artifacts' list")
    pkgs = []
    for a in doc["artifacts"]:
        if not isinstance(a, dict) or not a.get("name"):
            continue
        pkgs.append({
            "syft_id": a.get("id"),
            "name": a["name"],
            "version": a.get("version"),
            "type": a.get("type"),
            "purl": a.get("purl"),
            "locations": [
                loc.get("path") for loc in a.get("locations", []) if isinstance(loc, dict)
            ],
        })
    rels = doc.get("artifactRelationships") or []
    dep_rels = [
        {"parent": r.get("parent"), "child": r.get("child"), "type": r.get("type")}
        for r in rels if isinstance(r, dict) and r.get("type") in ("dependency-of", "depends-on")
    ]
    return {
        "packages": pkgs,
        "relationships": dep_rels,
        "relationship_kind": "edges" if dep_rels else "flat",
        "descriptor_version": (doc.get("descriptor") or {}).get("version"),
    }


def run_syft(repo_dir: str | Path, store: EvidenceStore, timeout: int = 300) -> dict[str, Any]:
    """Generate a source SBOM for ``repo_dir``; preserve raw output + log."""
    exe = shutil.which("syft")
    if exe is None:
        return {"status": "NOT_RUN", "reason": "syft not installed", "tool_version": None}
    version = syft_version()
    argv = ["syft", f"dir:{Path(repo_dir).as_posix()}", "-o", "syft-json", "-q"]
    try:
        res = subprocess.run([exe, *argv[1:]], capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "FAILED", "reason": f"syft did not complete: {exc.__class__.__name__}",
                "tool_version": version}
    safe_argv = ["syft", "dir:<repo>", "-o", "syft-json", "-q"]
    log_rel, log_sha = store.save_raw("syft.stderr.log", scrub_host_paths(res.stderr.decode("utf-8", "replace")).encode())
    raw_rel, raw_sha = store.save_raw("syft.json", res.stdout)
    ev = store.add(
        "SBOM", f"syft exit={res.returncode} argv={' '.join(safe_argv)}",
        tool_name="syft", tool_version=version, raw_artifact=raw_rel, raw_sha256=raw_sha,
        observed_value={"exit_code": res.returncode, "stderr_artifact": log_rel, "stderr_sha256": log_sha},
    )
    out: dict[str, Any] = {"tool_version": version, "evidence_id": ev, "raw_artifact": raw_rel,
                           "raw_sha256": raw_sha, "exit_code": res.returncode}
    if res.returncode != 0:
        return {**out, "status": "FAILED", "reason": f"syft exited {res.returncode}"}
    try:
        return {**out, "status": "COMPLETE", **parse_syft_json(res.stdout)}
    except ValueError as exc:
        return {**out, "status": "FAILED", "reason": str(exc)}
