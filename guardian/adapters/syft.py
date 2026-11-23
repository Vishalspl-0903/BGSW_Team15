"""Syft source-SBOM adapter (Role B). Never fabricates output.

If Syft is absent the result is ``status="NOT_RUN"``; a crash or malformed
output is ``FAILED`` with the raw bytes still preserved and hashed.

One Syft run writes two formats: syft-json (kept under ``raw/syft.json``, used
for the cross-check) and CycloneDX JSON (``sbom/syft.cdx.json``, the SBOM that
E's Grype adapter consumes). Both are hashed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
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


def parse_cyclonedx(raw: bytes) -> dict[str, Any]:
    """Validate a CycloneDX JSON BOM and extract components + dependency edges."""
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        raise ValueError(f"CycloneDX output is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("bomFormat") != "CycloneDX" or not isinstance(doc.get("components", []), list):
        raise ValueError("document is not a CycloneDX BOM with a 'components' list")
    pkgs = []
    for c in doc.get("components", []):
        if not isinstance(c, dict) or not c.get("name"):
            continue
        purl = c.get("purl")
        pkgs.append({"syft_id": c.get("bom-ref"), "name": c["name"], "version": c.get("version"),
                     "type": "npm" if isinstance(purl, str) and purl.startswith("pkg:npm/") else c.get("type"),
                     "purl": purl, "locations": []})
    rels = [{"parent": d.get("ref"), "child": child, "type": "depends-on"}
            for d in doc.get("dependencies", []) if isinstance(d, dict)
            for child in d.get("dependsOn", []) or []]
    return {"packages": pkgs, "relationships": rels, "relationship_kind": "edges" if rels else "flat",
            "descriptor_version": (doc.get("metadata") or {}).get("tools")}


def run_syft(repo_dir: str | Path, store: EvidenceStore, timeout: int = 300) -> dict[str, Any]:
    """Generate a source SBOM for ``repo_dir``; preserve raw output, CycloneDX and log."""
    exe = shutil.which("syft")
    if exe is None:
        return {"status": "NOT_RUN", "reason": "syft not installed", "tool_version": None}
    version = syft_version()
    with tempfile.TemporaryDirectory() as tmp:
        cdx_path = Path(tmp) / "syft.cdx.json"
        argv = [exe, f"dir:{Path(repo_dir).as_posix()}", "-o", "syft-json", "-o",
                f"cyclonedx-json={cdx_path.as_posix()}", "-q"]
        try:
            res = subprocess.run(argv, capture_output=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return {"status": "FAILED", "reason": f"syft did not complete: {exc.__class__.__name__}",
                    "tool_version": version}
        cdx_raw = cdx_path.read_bytes() if cdx_path.is_file() else None
    safe_argv = "syft dir:<repo> -o syft-json -o cyclonedx-json=<file> -q"
    log_rel, log_sha = store.save_raw("syft.stderr.log", scrub_host_paths(res.stderr.decode("utf-8", "replace")).encode())
    raw_rel, raw_sha = store.save_raw("syft.json", res.stdout)
    ev = store.add(
        "SBOM", f"syft exit={res.returncode} argv={safe_argv}",
        tool_name="syft", tool_version=version, raw_artifact=raw_rel, raw_sha256=raw_sha,
        observed_value={"exit_code": res.returncode, "stderr_artifact": log_rel, "stderr_sha256": log_sha},
    )
    out: dict[str, Any] = {"tool_version": version, "evidence_id": ev, "raw_artifact": raw_rel,
                           "raw_sha256": raw_sha, "exit_code": res.returncode,
                           "sbom_artifact": None, "sbom_sha256": None}
    if res.returncode != 0:
        return {**out, "status": "FAILED", "reason": f"syft exited {res.returncode}"}
    if cdx_raw is not None:
        sbom_rel, sbom_sha = store.save_raw("syft.cdx.json", cdx_raw, subdir="sbom")
        out.update(sbom_artifact=sbom_rel, sbom_sha256=sbom_sha)
        store.add("SBOM", "CycloneDX SBOM written by syft (consumed by the advisory scanner)",
                  tool_name="syft", tool_version=version, raw_artifact=sbom_rel, raw_sha256=sbom_sha)
    try:
        parsed = parse_syft_json(res.stdout)
    except ValueError as exc:
        return {**out, "status": "FAILED", "reason": str(exc)}
    out.update(status="COMPLETE", **parsed)
    if cdx_raw is None:
        out["cdx_warning"] = "syft produced no CycloneDX file"
    else:
        try:
            out["cdx_components"] = len(parse_cyclonedx(cdx_raw)["packages"])
        except ValueError as exc:
            out["cdx_warning"] = str(exc)
    return out
