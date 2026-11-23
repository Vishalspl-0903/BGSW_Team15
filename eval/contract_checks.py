"""Independent contract and referential-integrity checks (Role E, PROJECT.md 9, 15.E1, 21.4).

These checks work on plain JSON dictionaries so they can run before, and later
cross-check, C's ``validate-run``.  Enumerations are taken from
``guardian.schemas`` when that module is importable; otherwise the literal
values frozen in PROJECT.md section 9.1 are used.

Each function returns a list of human-readable violations (empty = pass).
"""

from __future__ import annotations

import re
from typing import Any, Iterable

_SPEC_ENUMS: dict[str, set[str]] = {
    "Coverage": {"RESOLVED", "PARTIAL", "DECLARED_ONLY", "UNSUPPORTED", "FAILED", "NOT_RUN"},
    "Resolution": {"RESOLVED", "DECLARED_ONLY", "UNKNOWN_VERSION", "CONFLICT"},
    "EvidenceBasis": {"TOOL_OBSERVED", "CORROBORATED", "RULE_MATCH", "INFERRED", "UNKNOWN"},
    "FindingType": {"VULNERABILITY", "SUSPICIOUS_CHANGE", "CI_POLICY", "CONTAINER_POLICY", "COVERAGE_GAP"},
    "FindingClass": {"CONFIRMED_ADVISORY", "SUSPICIOUS_INDICATOR", "CONFIGURATION_WEAKNESS", "COVERAGE_LIMITATION"},
    "Priority": {"P0", "P1", "P2", "P3", "NEEDS_REVIEW", "UNASSESSED"},
    "StageStatus": {"NOT_RUN", "RUNNING", "COMPLETE", "PARTIAL", "FAILED", "UNAVAILABLE", "BLOCKED"},
}
_EDGE_RELATIONSHIPS = {"CONTAINS_MODULE", "DECLARES", "DEPENDS_ON", "BUILDS_FROM", "OBSERVED_IN",
                       "INVOKES_DURING_BUILD", "INVOKES_DURING_INSTALL", "MAY_INVOKE"}
_EDGE_RESOLUTION = {"OBSERVED", "INFERRED", "UNRESOLVED"}
_DIRECTNESS = {"DIRECT", "TRANSITIVE", "UNRESOLVED"}
_SCOPES = {"production", "development", "optional", "peer", "build", "unknown"}
_SOURCE_SCOPE = {"SOURCE", "ARTIFACT", "BOTH", "UNKNOWN"}
_IMAGE_PRESENCE = {"OBSERVED", "NOT_OBSERVED_IN_SCANNED_IMAGE", "NOT_CHECKED", "UNKNOWN"}
_PACKAGE_SOURCE = {"REGISTRY", "GIT", "TARBALL", "WORKSPACE", "LOCAL", "UNKNOWN"}
_PATH_STATUS = {"FOUND", "NO_KNOWN_PATH", "UNRESOLVED", "NOT_APPLICABLE"}
_EXEC_STAGE = {"INSTALL", "BUILD", "CI", "RUNTIME", "DEV_TEST", "UNKNOWN"}
_EXEC_EVIDENCE = {"CONFIRMED", "POTENTIAL", "NOT_ESTABLISHED", "NOT_ANALYZED"}
_FIRST_SEEN = {"REAL_UPSTREAM", "SEEDED_SIMULATION", "LOCAL_FIXTURE"}
_EVIDENCE_KIND = {"MANIFEST", "LOCKFILE", "SBOM", "ADVISORY", "RULE_MATCH", "TOOL_LOG", "CI_CONFIG",
                  "VALIDATION", "MODEL_OUTPUT"}
_FORBIDDEN_STATUS_WORDS = {"SAFE", "DONE_SUCCESS", "FULLY_VERIFIED", "MALICIOUS", "CLEAN"}
_FACTUAL_FINDINGS = {"VULNERABILITY", "SUSPICIOUS_CHANGE", "CI_POLICY", "CONTAINER_POLICY"}
_CONSTRAINT_CHARS = re.compile(r"[\^~<>=*|\s]|^x$|\.x\b|^latest$|^next$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+00:00)$")
_HOST_PATH = re.compile(r"(^|[\s\"'(=])([A-Za-z]:[\\/]|\\\\[^\\]|/home/|/Users/|/root/|/var/folders/)")


def enum_values(name: str) -> set[str]:
    """Values of a canonical enum: C's model when merged, else the frozen spec literals."""
    try:
        from guardian import schemas  # type: ignore[attr-defined]

        enum = getattr(schemas, name)
        return {member.value for member in enum}
    except Exception:  # noqa: BLE001 - schemas not merged yet, or enum renamed
        return set(_SPEC_ENUMS[name])


def _as_dict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from _strings(value)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            yield from _strings(value)


def host_path_leaks(obj: Any) -> list[str]:
    """Strings that look like absolute host paths (never allowed in run artifacts)."""
    return sorted({s[:120] for s in _strings(obj) if _HOST_PATH.search(s)})


def _is_relative_path(value: str | None) -> bool:
    if value is None:
        return True
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        return False
    return ".." not in value.replace("\\", "/").split("/")


# ----------------------------------------------------------------------------- graph
def check_graph_bundle(graph: Any, evidence_ids: set[str] | None = None) -> list[str]:
    g = _as_dict(graph)
    out: list[str] = []
    for key in ("schema_version", "scan_id", "modules", "components", "edges", "coverage_summary"):
        if key not in g:
            out.append(f"graph: missing top-level field {key!r}")
    modules = g.get("modules") or []
    components = g.get("components") or []
    edges = g.get("edges") or []
    coverage_enum = enum_values("Coverage")
    resolution_enum = enum_values("Resolution")

    module_ids = [m.get("module_id") for m in modules]
    occ_ids = [c.get("occurrence_id") for c in components]
    edge_ids = [e.get("edge_id") for e in edges]
    for label, ids in (("module_id", module_ids), ("occurrence_id", occ_ids), ("edge_id", edge_ids)):
        dupes = sorted({i for i in ids if ids.count(i) > 1})
        if dupes:
            out.append(f"graph: duplicate {label} values {dupes[:5]}")
        if any(not i for i in ids):
            out.append(f"graph: empty {label}")
    node_ids = set(module_ids) | set(occ_ids)

    artifact_scanned = any(m.get("artifact_sbom_status") in {"COMPLETE", "PARTIAL"} for m in modules)
    for m in modules:
        mid = m.get("module_id")
        if m.get("coverage") not in coverage_enum:
            out.append(f"module {mid}: coverage {m.get('coverage')!r} not in Coverage enum")
        if m.get("coverage") != "RESOLVED" and not (m.get("coverage_reason") or "").strip():
            out.append(f"module {mid}: coverage {m.get('coverage')} needs a non-empty coverage_reason")
        if not _is_relative_path(m.get("relative_path")):
            out.append(f"module {mid}: relative_path {m.get('relative_path')!r} is not repository-relative")

    for c in components:
        oid = c.get("occurrence_id")
        if c.get("module_id") not in set(module_ids):
            out.append(f"component {oid}: module_id {c.get('module_id')!r} does not exist")
        if c.get("resolution") not in resolution_enum:
            out.append(f"component {oid}: resolution {c.get('resolution')!r} not in Resolution enum")
        version = c.get("resolved_version")
        if c.get("resolution") == "RESOLVED" and not version:
            out.append(f"component {oid}: RESOLVED without resolved_version")
        if version is not None and _CONSTRAINT_CHARS.search(str(version)):
            out.append(f"component {oid}: resolved_version {version!r} looks like a constraint, not an exact version")
        if version is None and c.get("package_key"):
            out.append(f"component {oid}: package_key set although the version is unresolved")
        if c.get("directness") not in _DIRECTNESS:
            out.append(f"component {oid}: directness {c.get('directness')!r} invalid")
        bad_scopes = set(c.get("dependency_scopes") or []) - _SCOPES
        if bad_scopes:
            out.append(f"component {oid}: unknown dependency_scopes {sorted(bad_scopes)}")
        if c.get("source_scope") not in _SOURCE_SCOPE:
            out.append(f"component {oid}: source_scope {c.get('source_scope')!r} invalid")
        if c.get("image_presence") not in _IMAGE_PRESENCE:
            out.append(f"component {oid}: image_presence {c.get('image_presence')!r} invalid")
        elif not artifact_scanned and c.get("image_presence") in {"OBSERVED", "NOT_OBSERVED_IN_SCANNED_IMAGE"}:
            out.append(f"component {oid}: image_presence {c.get('image_presence')} but no image was scanned")
        if c.get("package_source_type") not in _PACKAGE_SOURCE:
            out.append(f"component {oid}: package_source_type {c.get('package_source_type')!r} invalid")
        if evidence_ids is not None:
            for ev in c.get("evidence_ids") or []:
                if ev not in evidence_ids:
                    out.append(f"component {oid}: evidence id {ev!r} does not exist")

    for e in edges:
        eid = e.get("edge_id")
        if e.get("source_id") not in node_ids:
            out.append(f"edge {eid}: source_id {e.get('source_id')!r} is not a module or occurrence")
        if e.get("target_id") not in node_ids:
            out.append(f"edge {eid}: target_id {e.get('target_id')!r} is not a module or occurrence")
        if e.get("relationship") not in _EDGE_RELATIONSHIPS:
            out.append(f"edge {eid}: relationship {e.get('relationship')!r} invalid")
        if e.get("resolution") not in _EDGE_RESOLUTION:
            out.append(f"edge {eid}: resolution {e.get('resolution')!r} invalid")
        if e.get("resolution") == "OBSERVED" and not e.get("evidence_ids"):
            out.append(f"edge {eid}: OBSERVED edge without evidence_ids")
        if evidence_ids is not None:
            for ev in e.get("evidence_ids") or []:
                if ev not in evidence_ids:
                    out.append(f"edge {eid}: evidence id {ev!r} does not exist")

    summary = g.get("coverage_summary") or {}
    if summary:
        if summary.get("total_modules") != len(modules):
            out.append(f"coverage_summary.total_modules {summary.get('total_modules')} != {len(modules)} modules")
        for cov in ("RESOLVED", "PARTIAL", "DECLARED_ONLY", "UNSUPPORTED", "FAILED"):
            key = f"{cov.lower()}_modules"
            if key in summary and summary[key] != sum(1 for m in modules if m.get("coverage") == cov):
                out.append(f"coverage_summary.{key} does not match module records")
    for leak in host_path_leaks(g):
        out.append(f"graph: absolute host path leaked: {leak!r}")
    return out


# ----------------------------------------------------------------------------- evidence
def check_evidence_records(records: list[Any], scan_id: str | None = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in records:
        r = _as_dict(raw)
        eid = r.get("evidence_id")
        if not eid:
            out.append("evidence: record without evidence_id")
            continue
        if eid in seen:
            out.append(f"evidence {eid}: duplicate id")
        seen.add(eid)
        if scan_id is not None and r.get("scan_id") != scan_id:
            out.append(f"evidence {eid}: scan_id {r.get('scan_id')!r} != {scan_id!r}")
        if r.get("kind") not in _EVIDENCE_KIND:
            out.append(f"evidence {eid}: kind {r.get('kind')!r} invalid")
        if r.get("raw_sha256") is not None and not _SHA256.match(str(r.get("raw_sha256"))):
            out.append(f"evidence {eid}: raw_sha256 is not lowercase sha256 hex")
        if r.get("raw_artifact") and r.get("raw_sha256") is None:
            out.append(f"evidence {eid}: raw_artifact without raw_sha256")
        for field in ("raw_artifact", "source_path"):
            if not _is_relative_path(r.get(field)):
                out.append(f"evidence {eid}: {field} {r.get(field)!r} is not relative")
        if not _RFC3339_UTC.match(str(r.get("recorded_at") or "")):
            out.append(f"evidence {eid}: recorded_at {r.get('recorded_at')!r} is not RFC3339 UTC")
        if not (r.get("observation") or "").strip():
            out.append(f"evidence {eid}: empty observation")
        for leak in host_path_leaks(r):
            out.append(f"evidence {eid}: absolute host path leaked: {leak!r}")
    return out


# ----------------------------------------------------------------------------- findings
def check_findings(findings: list[Any], scan_id: str | None = None, evidence_ids: set[str] | None = None,
                   graph: Any = None) -> list[str]:
    out: list[str] = []
    g = _as_dict(graph) if graph is not None else None
    occ_ids = {c.get("occurrence_id") for c in (g or {}).get("components") or []}
    node_ids = occ_ids | {m.get("module_id") for m in (g or {}).get("modules") or []}
    module_ids = {m.get("module_id") for m in (g or {}).get("modules") or []}
    seen: set[str] = set()
    type_enum, class_enum = enum_values("FindingType"), enum_values("FindingClass")
    prio_enum, basis_enum = enum_values("Priority"), enum_values("EvidenceBasis")
    for raw in findings:
        f = _as_dict(raw)
        fid = f.get("finding_id")
        if not fid:
            out.append("finding: missing finding_id")
            continue
        if fid in seen:
            out.append(f"finding {fid}: duplicate finding_id")
        seen.add(fid)
        if scan_id is not None and f.get("scan_id") != scan_id:
            out.append(f"finding {fid}: scan_id {f.get('scan_id')!r} != {scan_id!r}")
        ftype = f.get("finding_type")
        if ftype not in type_enum:
            out.append(f"finding {fid}: finding_type {ftype!r} invalid")
        if f.get("classification") not in class_enum:
            out.append(f"finding {fid}: classification {f.get('classification')!r} invalid")
        if f.get("priority") not in prio_enum:
            out.append(f"finding {fid}: priority {f.get('priority')!r} invalid")
        if f.get("evidence_basis") not in basis_enum:
            out.append(f"finding {fid}: evidence_basis {f.get('evidence_basis')!r} invalid")
        if f.get("path_status") not in _PATH_STATUS:
            out.append(f"finding {fid}: path_status {f.get('path_status')!r} invalid")
        if f.get("execution_stage") not in _EXEC_STAGE:
            out.append(f"finding {fid}: execution_stage {f.get('execution_stage')!r} invalid")
        if f.get("execution_evidence") not in _EXEC_EVIDENCE:
            out.append(f"finding {fid}: execution_evidence {f.get('execution_evidence')!r} invalid")
        if f.get("first_seen_in") not in _FIRST_SEEN:
            out.append(f"finding {fid}: first_seen_in {f.get('first_seen_in')!r} invalid")
        for field in ("classification", "priority", "path_status", "evidence_basis"):
            if str(f.get(field)).upper() in _FORBIDDEN_STATUS_WORDS:
                out.append(f"finding {fid}: forbidden status word in {field}")
        if ftype in _FACTUAL_FINDINGS and not f.get("evidence_ids"):
            out.append(f"finding {fid}: factual finding without evidence_ids")
        if evidence_ids is not None:
            for ev in f.get("evidence_ids") or []:
                if ev not in evidence_ids:
                    out.append(f"finding {fid}: evidence id {ev!r} does not exist")
        if ftype == "VULNERABILITY":
            if not f.get("advisory_ids"):
                out.append(f"finding {fid}: vulnerability without advisory_ids")
            if f.get("classification") != "CONFIRMED_ADVISORY":
                out.append(f"finding {fid}: vulnerability must be classified CONFIRMED_ADVISORY")
        if ftype in {"SUSPICIOUS_CHANGE", "CI_POLICY", "CONTAINER_POLICY"} and not f.get("rule_id"):
            out.append(f"finding {fid}: rule-based finding without rule_id")
        path = f.get("dependency_path_node_ids") or []
        if f.get("path_status") == "FOUND" and not path:
            out.append(f"finding {fid}: path_status FOUND with an empty dependency path")
        if f.get("path_status") != "FOUND" and path:
            out.append(f"finding {fid}: dependency path given although path_status is {f.get('path_status')}")
        score = f.get("cvss_score")
        if score is not None and not (0.0 <= float(score) <= 10.0):
            out.append(f"finding {fid}: cvss_score {score} out of range")
        if g is not None:
            for oid in f.get("occurrence_ids") or []:
                if oid not in occ_ids:
                    out.append(f"finding {fid}: occurrence {oid!r} not in graph")
            for mid in f.get("module_ids") or []:
                if mid not in module_ids:
                    out.append(f"finding {fid}: module {mid!r} not in graph")
            for nid in path:
                if nid not in node_ids:
                    out.append(f"finding {fid}: path node {nid!r} not in graph")
        if not isinstance(f.get("uncertainties"), list):
            out.append(f"finding {fid}: uncertainties must be a list")
        for leak in host_path_leaks(f):
            out.append(f"finding {fid}: absolute host path leaked: {leak!r}")
    return out


def check_stage_record(stage: dict[str, Any]) -> list[str]:
    """A scan-stage record must never turn a failed or missing scan into a zero result."""
    out: list[str] = []
    status = stage.get("status")
    if status not in enum_values("StageStatus"):
        out.append(f"stage {stage.get('stage')}: status {status!r} invalid")
    if status == "COMPLETE":
        if stage.get("known_matches") is None:
            out.append(f"stage {stage.get('stage')}: COMPLETE without a known_matches count")
        if not stage.get("completed_at"):
            out.append(f"stage {stage.get('stage')}: COMPLETE without completed_at")
    elif stage.get("known_matches") not in (None,) and status in {"FAILED", "UNAVAILABLE", "BLOCKED", "NOT_RUN"}:
        out.append(f"stage {stage.get('stage')}: status {status} must report known_matches as null, not a number")
    if status in {"FAILED", "UNAVAILABLE", "BLOCKED", "PARTIAL"} and not (stage.get("reason") or "").strip():
        out.append(f"stage {stage.get('stage')}: status {status} without a reason")
    return out
