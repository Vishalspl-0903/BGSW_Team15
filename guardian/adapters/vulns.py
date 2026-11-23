"""Known-vulnerability adapter: Grype on B's SBOM -> canonical findings (Role E).

PROJECT.md references: 6.6, 9.4 (public signature), 18.1-18.4, 20.2, 15.E2.

Guarantees
    * Grype runs only on an SBOM that already exists (never on repository code), with an
      argument list, a timeout, no shell, a reduced environment and no app-update check.
    * A scan that could not run is reported as UNAVAILABLE / FAILED / BLOCKED with a reason
      and ``known_matches = null``; it is never turned into "0 vulnerabilities".
    * Advisory ids are merged only through the scanner's own alias metadata
      (see ``guardian.analysis.advisory_normalizer``); every match stays as evidence.
    * Exact versions only: a match is attached to graph occurrences whose resolved version
      equals the scanned version.  Matches that cannot be mapped stay visible as findings
      with an explicit uncertainty instead of being dropped.
    * Stored raw outputs are stripped of absolute host paths before hashing.

Outputs are plain dictionaries shaped like the frozen PROJECT.md section 9 models.  When
``guardian.schemas`` is importable they are validated into C's models; until then the
dictionaries are returned unchanged so the rest of the pipeline can be tested.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from guardian.analysis.advisory_normalizer import (
    group_observations,
    initial_priority,
    observations_from_grype,
)

STAGE = "vulnerability_intelligence"
TOOL = "grype"
SCHEMA_VERSION = "1.0"
_DEFAULT_TIMEOUT_S = 600
_MAX_REPORT_BYTES = 200 * 1024 * 1024
_SOURCE_KIND_TO_FIRST_SEEN = {"GIT_PUBLIC": "REAL_UPSTREAM", "CACHED_SNAPSHOT": "REAL_UPSTREAM",
                              "LOCAL_FIXTURE": "LOCAL_FIXTURE"}
_ABS_PATH = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\|/(?:home|Users|root|tmp|var|private)/)")


class VulnerabilityScanError(RuntimeError):
    """Raised only for caller errors (bad arguments); scan problems become stage records."""


# ----------------------------------------------------------------------------- small helpers
def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stable_id(prefix: str, *parts: Any) -> str:
    canonical = json.dumps(list(parts), sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"{prefix}:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()[:20]}"


def _as_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


def redact_host_paths(obj: Any, replacements: list[tuple[str, str]]) -> Any:
    """Replace absolute host paths inside every string of a JSON-like structure."""
    pairs = []
    for prefix, placeholder in replacements:
        if not prefix:
            continue
        for variant in {prefix, prefix.replace("\\", "/"), prefix.replace("/", "\\")}:
            pairs.append((variant, placeholder))
    pairs.sort(key=lambda p: len(p[0]), reverse=True)

    def fix(text: str) -> str:
        for prefix, placeholder in pairs:
            if prefix in text:
                text = text.replace(prefix, placeholder)
        if _ABS_PATH.match(text):
            tail = re.split(r"[\\/]", text.rstrip("\\/"))[-1]
            text = f"<host-path>/{tail}"
        return text

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return fix(value)
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        return value

    return walk(obj)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"<outside-run>/{path.name}"


def _write_json(path: Path, data: Any) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(data, indent=1, sort_keys=False, ensure_ascii=False) + "\n").encode("utf-8")
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def _validate(model_name: str, payload: dict[str, Any]) -> Any:
    try:
        from guardian import schemas  # type: ignore[attr-defined]
    except (ImportError, ModuleNotFoundError):
        return payload
    model = getattr(schemas, model_name, None)
    return payload if model is None else model.model_validate(payload)


def _first_seen(run_dir: Path | None) -> str:
    """Provenance label from C's metadata; unknown provenance is never labelled real."""
    if run_dir is not None:
        meta = run_dir / "metadata.json"
        if meta.is_file():
            try:
                kind = json.loads(meta.read_text(encoding="utf-8")).get("source_kind")
                return _SOURCE_KIND_TO_FIRST_SEEN.get(kind, "LOCAL_FIXTURE")
            except (OSError, ValueError):
                pass
    return "LOCAL_FIXTURE"


def _stage(status: str, *, attempted: bool, reason: str | None = None, tool_version: str | None = None,
           known_matches: int | None = None, completed_at: str | None = None,
           evidence_ids: list[str] | None = None) -> Any:
    """Exactly the PROJECT.md 18.3 StageRecord fields (C's model forbids extras)."""
    record = {"stage": STAGE, "status": status, "attempted": attempted, "tool": TOOL,
              "tool_version": tool_version, "reason": reason, "completed_at": completed_at,
              "known_matches": known_matches if status == "COMPLETE" else None,
              "evidence_ids": evidence_ids or []}
    return _validate("StageRecord", record)


def _result(stage: Any, findings: list | None = None, evidence: list | None = None,
            details: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"stage": stage, "stage_details": details or {}, "findings": findings or [], "evidence": evidence or []}


# ----------------------------------------------------------------------------- graph mapping
def _graph_index(graph: dict[str, Any]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    index: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for comp in graph.get("components") or []:
        if comp.get("resolution") != "RESOLVED" or not comp.get("resolved_version"):
            continue
        key = (str(comp.get("ecosystem")), str(comp.get("name")), str(comp.get("resolved_version")))
        index.setdefault(key, []).append(comp)
    return index


def _dependency_path(run_dir: Path | None, scan_id: str, module_id: str, occurrence_id: str) -> tuple[str, list[str], str | None]:
    """Ask B's public path query; never compute paths here (B owns graph traversal)."""
    if run_dir is None or not (run_dir / "graph.sqlite").is_file():
        return "UNRESOLVED", [], "dependency path not computed: graph.sqlite from B's graph builder is not available"
    try:
        from guardian.analysis.paths import get_dependency_path  # type: ignore[import-not-found]
    except (ImportError, ModuleNotFoundError):
        return "UNRESOLVED", [], "dependency path not computed: B's path query module is not merged"
    try:
        result = get_dependency_path(str(run_dir / "graph.sqlite"), scan_id, module_id, occurrence_id)
    except Exception as exc:  # noqa: BLE001 - path failure must not drop the finding
        return "UNRESOLVED", [], f"dependency path query failed: {type(exc).__name__}"
    status = str(result.get("status") or "UNRESOLVED")
    nodes = list(result.get("node_ids") or []) if status == "FOUND" else []
    if status not in {"FOUND", "NO_KNOWN_PATH", "UNRESOLVED", "NOT_APPLICABLE"}:
        return "UNRESOLVED", [], f"path query returned status {status!r}"
    return status, nodes, None


# ----------------------------------------------------------------------------- pure conversion
def findings_from_grype_report(
    scan_id: str,
    report: dict[str, Any],
    graph: Any,
    *,
    raw_artifact: str,
    raw_sha256: str,
    tool_version: str | None,
    advisory_as_of: str | None,
    recorded_at: str | None = None,
    first_seen_in: str = "LOCAL_FIXTURE",
    run_dir: Path | None = None,
) -> dict[str, Any]:
    """Convert a (stored, redacted) Grype JSON report into findings + evidence records.

    Pure apart from the optional call to B's path query.  Returns
    ``{"findings": [...], "evidence": [...], "unmapped_matches": int, "raw_matches": int}``.
    """
    graph = _as_dict(graph) or {}
    recorded_at = recorded_at or _now()
    observations = observations_from_grype(report)
    groups = group_observations(observations)
    index = _graph_index(graph)

    evidence: list[dict[str, Any]] = []
    evidence_by_pointer: dict[str, str] = {}
    for obs in observations:
        eid = _stable_id("ev", scan_id, "ADVISORY", raw_sha256, obs["pointer"])
        evidence_by_pointer[obs["pointer"]] = eid
        pkg = obs["package"] or {}
        evidence.append({
            "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "evidence_id": eid, "kind": "ADVISORY",
            "tool_name": TOOL, "tool_version": tool_version, "source_path": None, "json_pointer": obs["pointer"],
            "line_start": None, "line_end": None,
            "observed_value": {"advisory_id": obs["advisory_id"], "related_ids": [r["id"] for r in obs["related"]],
                               "purl": pkg.get("purl"), "severity": obs["severity"],
                               "fix_versions": obs["fix_versions"], "fix_state": obs["fix_state"],
                               "match_types": obs["match_types"]},
            "raw_artifact": raw_artifact, "raw_sha256": raw_sha256,
            "observation": (f"{TOOL} matched {pkg.get('name')}@{pkg.get('version')} to {obs['advisory_id']}"
                            f" ({obs['severity'] or 'severity not published'})"),
            "recorded_at": recorded_at,
        })

    findings: list[dict[str, Any]] = []
    unmapped = 0
    for group in groups:
        pkg = group["package"]
        ids = group["advisory_ids"]
        obs_eids = [evidence_by_pointer[o["pointer"]] for o in group["observations"]]
        uncertainties = ["Reachability of the vulnerable code in this application is not analyzed.",
                         "Exploitability in this application is not established."]
        if advisory_as_of is None:
            uncertainties.append("Advisory database build time was not reported by the scanner.")
        if group["severity_conflict"]:
            pairs = ", ".join(f"{k}={v}" for k, v in sorted(group["severity_by_source"].items()))
            uncertainties.append(f"Sources disagree on severity ({pairs}); the matched record's value is shown.")
        occurrences = index.get((pkg["ecosystem"], pkg["name"], pkg["version"]), []) if pkg else []
        occurrence_ids = sorted({c["occurrence_id"] for c in occurrences})
        module_ids = sorted({c["module_id"] for c in occurrences if c.get("module_id")})
        component_eids = sorted({e for c in occurrences for e in c.get("evidence_ids") or []})
        path_status, path_nodes = "UNRESOLVED", []
        if not pkg:
            uncertainties.append("Scanner match has no usable package identity (purl/name/version).")
            unmapped += 1
        elif not occurrences:
            uncertainties.append(f"UNRESOLVED_COMPONENT: {pkg['purl'] or pkg['name']} could not be mapped to a "
                                 "resolved graph occurrence with the same exact version.")
            unmapped += 1
        else:
            first = sorted(occurrences, key=lambda c: (str(c.get("module_id")), c["occurrence_id"]))[0]
            path_status, path_nodes, note = _dependency_path(run_dir, scan_id, first.get("module_id"), first["occurrence_id"])
            if note:
                uncertainties.append(note)
            if len(occurrences) > 1:
                uncertainties.append(f"Affects {len(occurrences)} occurrences in {len(module_ids)} module(s); "
                                     "the dependency path shown is for one representative occurrence.")
        fixes = group["fix_versions"]
        if fixes:
            recommendations = [f"Scanner fix data lists fixed version(s) {', '.join(fixes)}; verify compatibility "
                               "and audit the candidate version before upgrading."]
        else:
            recommendations = ["No fixed version is published in the scanner data; consider mitigation or escalation."]
        name = f"{pkg['name']}@{pkg['version']}" if pkg else "unmapped package"
        summary = group["description"][:300] + ("..." if len(group["description"]) > 300 else "")
        description = (f"{TOOL} {tool_version or ''} matched {name} to advisory {', '.join(ids)}"
                       f"{' (aliases: ' + ', '.join(group['aliases']) + ')' if group['aliases'] else ''}"
                       f" using {', '.join(group['match_types']) or 'an unspecified match type'}."
                       f"{' Advisory summary: ' + summary if summary else ''}")
        severity = group["severity_label"]
        is_mapped = bool(pkg and occurrences)
        finding_type = "VULNERABILITY" if is_mapped else "COVERAGE_GAP"
        classification = "CONFIRMED_ADVISORY" if is_mapped else "COVERAGE_LIMITATION"
        if not is_mapped:
            description += (" This advisory match could not be mapped to a resolved graph component; "
                            "it is recorded as a coverage gap, not a confirmed vulnerability.")
        findings.append({
            "schema_version": SCHEMA_VERSION, "scan_id": scan_id,
            "finding_id": _stable_id("fnd", scan_id, finding_type,
                                     [pkg["ecosystem"], pkg["name"], pkg["version"]] if pkg else None,
                                     sorted(ids + group["aliases"])),
            "finding_type": finding_type,
            "title": f"{name}: {group['display_id']}" + (f" ({severity})" if severity else ""),
            "description": description,
            "module_ids": module_ids, "occurrence_ids": occurrence_ids,
            "advisory_ids": ids, "advisory_urls": group["urls"][:10],
            "rule_id": None, "severity_label": severity, "cvss_score": group["cvss_score"],
            "priority": initial_priority(severity) if is_mapped else "NEEDS_REVIEW",
            "evidence_ids": obs_eids + component_eids,
            "dependency_path_node_ids": path_nodes if path_status == "FOUND" else [],
            "path_status": path_status,
            "execution_stage": "UNKNOWN", "execution_evidence": "NOT_ANALYZED",
            "evidence_basis": "TOOL_OBSERVED" if is_mapped else "UNKNOWN",
            "uncertainties": uncertainties, "recommendations": recommendations,
            "classification": classification,
            "advisory_aliases": group["aliases"],
            "first_seen_in": first_seen_in,
            "advisory_as_of": advisory_as_of,
            "scanner_names": [TOOL],
        })
    findings.sort(key=lambda f: (f["title"], f["finding_id"]))
    return {"findings": findings, "evidence": evidence, "unmapped_matches": unmapped,
            "raw_matches": len(observations)}


# ----------------------------------------------------------------------------- live scan
def _find_sbom(run_dir: Path) -> tuple[Path | None, str | None]:
    sbom_dir = run_dir / "sbom"
    if not sbom_dir.is_dir():
        return None, "no sbom/ directory in the run folder (B's source SBOM is required)"
    candidates = sorted(p for p in sbom_dir.glob("*.json") if p.is_file())
    if not candidates:
        return None, "sbom/ contains no JSON SBOM"
    preferred = [p for p in candidates if "source" in p.name.lower() and "cdx" in p.name.lower()]
    if len(preferred) == 1:
        return preferred[0], None
    if len(candidates) == 1:
        return candidates[0], None
    return None, f"ambiguous SBOM choice in sbom/: {[p.name for p in candidates]}; pass sbom_path explicitly"


def _grype_env(auto_update_db: bool) -> dict[str, str]:
    keep = ("PATH", "SYSTEMROOT", "TEMP", "TMP", "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOME",
            "XDG_CACHE_HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
    env = {k: v for k, v in os.environ.items() if k in keep or k.startswith("GRYPE_DB_CACHE")}
    env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"
    env["GRYPE_DB_AUTO_UPDATE"] = "true" if auto_update_db else "false"
    return env


def _run(argv: list[str], env: dict[str, str], timeout_s: int) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, timeout=timeout_s, env=env, shell=False, check=False)


def run_vulnerability_intelligence(
    scan_id: str,
    graph: Any,
    run_dir: str,
    *,
    sbom_path: str | None = None,
    grype_executable: str | None = None,
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    auto_update_db: bool = False,
) -> dict[str, Any]:
    """Run Grype on B's SBOM and return ``{"stage", "stage_details", "findings", "evidence"}``.

    ``stage`` holds exactly the StageRecord fields; extra facts (database build time, raw and
    unmapped match counts, SBOM path) are in ``stage_details``.  Never raises for scan
    problems; they are expressed in the stage record.
    """
    if not scan_id:
        raise VulnerabilityScanError("scan_id is required")
    run = Path(run_dir)
    run.mkdir(parents=True, exist_ok=True)
    graph_dict = _as_dict(graph) or {}

    sbom = Path(sbom_path) if sbom_path else None
    if sbom is None:
        sbom, why = _find_sbom(run)
        if sbom is None:
            return _result(_stage("BLOCKED", attempted=False, reason=why))
    if not sbom.is_file():
        return _result(_stage("BLOCKED", attempted=False, reason="SBOM file does not exist"))

    exe = grype_executable or os.environ.get("GUARDIAN_GRYPE") or shutil.which("grype")
    if not exe or not Path(exe).is_file():
        return _result(_stage("UNAVAILABLE", attempted=False, reason="grype executable not found (PATH or GUARDIAN_GRYPE)"))

    env = _grype_env(auto_update_db)
    raw_dir = run / "raw" / "grype"
    raw_dir.mkdir(parents=True, exist_ok=True)
    try:
        version_proc = _run([exe, "version", "-o", "json"], env, 60)
        tool_version = json.loads(version_proc.stdout.decode("utf-8", "replace") or "{}").get("version")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        tool_version = None

    db_status: dict[str, Any] = {}
    try:
        db_proc = _run([exe, "db", "status", "-o", "json"], env, 120)
        if db_proc.returncode == 0:
            db_status = json.loads(db_proc.stdout.decode("utf-8", "replace") or "{}")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        db_status = {}
    db_path = str(db_status.get("path") or "")
    replacements = [(str(run.resolve()), "<run-dir>"), (str(sbom.resolve().parent), "<sbom-dir>"),
                    (str(Path(db_path).parent) if db_path else "", "<grype-db-dir>"),
                    (str(Path(db_path).parent.parent) if db_path else "", "<grype-db-cache>"),
                    (str(Path.home()), "<home>")]
    advisory_as_of = db_status.get("built")
    db_sha = _write_json(raw_dir / "db-status.json", redact_host_paths(db_status, replacements)) if db_status else None

    try:
        proc = _run([exe, f"sbom:{sbom}", "-o", "json", "-q"], env, timeout_s)
    except subprocess.TimeoutExpired:
        return _result(_stage("FAILED", attempted=True, tool_version=tool_version,
                              reason=f"grype timed out after {timeout_s}s"))
    except OSError as exc:
        return _result(_stage("FAILED", attempted=True, tool_version=tool_version,
                              reason=f"grype could not start: {type(exc).__name__}"))

    stderr = redact_host_paths(proc.stderr.decode("utf-8", "replace")[-4000:], replacements)
    (raw_dir / "grype.stderr.log").write_text(stderr, encoding="utf-8")
    if proc.returncode != 0:
        lowered = stderr.lower()
        db_problem = any(word in lowered for word in ("database", "vulnerability db", "db status", "no db"))
        status = "UNAVAILABLE" if db_problem else "FAILED"
        return _result(_stage(status, attempted=True, tool_version=tool_version,
                              reason=f"grype exited with {proc.returncode}: {stderr.strip()[-300:] or 'no stderr'}"))
    if len(proc.stdout) > _MAX_REPORT_BYTES:
        return _result(_stage("FAILED", attempted=True, tool_version=tool_version,
                              reason="grype report exceeds the size limit"))
    try:
        report = json.loads(proc.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return _result(_stage("FAILED", attempted=True, tool_version=tool_version,
                              reason="grype output is not valid JSON"))
    if not isinstance(report, dict) or not isinstance(report.get("matches"), list):
        return _result(_stage("FAILED", attempted=True, tool_version=tool_version,
                              reason="grype output has an unsupported schema (no 'matches' list)"))

    report = redact_host_paths(report, replacements)
    raw_sha = _write_json(raw_dir / "grype.json", report)
    raw_rel = _relative(raw_dir / "grype.json", run)
    recorded_at = _now()
    converted = findings_from_grype_report(
        scan_id, report, graph_dict, raw_artifact=raw_rel, raw_sha256=raw_sha, tool_version=tool_version,
        advisory_as_of=advisory_as_of, recorded_at=recorded_at, first_seen_in=_first_seen(run), run_dir=run)

    log_eid = _stable_id("ev", scan_id, "TOOL_LOG", raw_sha, "/descriptor")
    converted["evidence"].append({
        "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "evidence_id": log_eid, "kind": "TOOL_LOG",
        "tool_name": TOOL, "tool_version": tool_version, "source_path": None, "json_pointer": "/descriptor",
        "line_start": None, "line_end": None,
        "observed_value": {"sbom": _relative(sbom, run), "database_built": advisory_as_of,
                           "database_schema": db_status.get("schemaVersion"), "raw_matches": converted["raw_matches"],
                           "db_status_sha256": db_sha},
        "raw_artifact": raw_rel, "raw_sha256": raw_sha,
        "observation": f"{TOOL} completed on {_relative(sbom, run)} with {converted['raw_matches']} raw match(es)",
        "recorded_at": recorded_at,
    })
    stage = _stage("COMPLETE", attempted=True, tool_version=tool_version, completed_at=recorded_at,
                   known_matches=len(converted["findings"]), evidence_ids=[log_eid])
    details = {"advisory_as_of": advisory_as_of, "database_schema": db_status.get("schemaVersion"),
               "raw_matches": converted["raw_matches"], "unmapped_matches": converted["unmapped_matches"],
               "sbom": _relative(sbom, run)}
    return _result(stage,
                   [_validate("Finding", f) for f in converted["findings"]],
                   [_validate("Evidence", e) for e in converted["evidence"]],
                   details)


def scan_known_vulnerabilities(scan_id: str, graph: Any, run_dir: str) -> list[Any]:
    """Public contract (PROJECT.md 9.4).  Use ``run_vulnerability_intelligence`` for the stage record."""
    result = run_vulnerability_intelligence(scan_id, graph, run_dir)
    stage = _as_dict(result["stage"])
    if stage["status"] != "COMPLETE":
        raise VulnerabilityScanError(f"Advisory scan {stage['status']}: {stage.get('reason')}")
    return result["findings"]
