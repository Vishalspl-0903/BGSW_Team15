"""D5 - GitHub Actions workflow policy detector (Role E, PROJECT.md 6.7, 15.E2, 19.3).

Static, read-only inspection of ``.github/workflows/*.yml|yaml``.  Nothing is executed.

Rules (each hit is a *configuration weakness*, never proof of compromise)
    D5-UNPINNED-ACTION         ``uses: owner/repo[/path]@ref`` (step action or reusable
                               workflow) whose ref is not a full 40-hex commit SHA.
                               Local ``./`` actions are never flagged.
    D5-UNPINNED-DOCKER-IMAGE   ``uses: docker://image`` without an ``@sha256:`` digest.
    D5-WRITE-PERMISSIONS       workflow-level permissions that grant write access
                               (``write-all`` or any ``<scope>: write``), or job-level
                               ``write-all``.  Job-level single write scopes are the
                               recommended least-privilege pattern and are not flagged.
    D5-UNPARSED-WORKFLOW       a workflow file that could not be read or parsed; reported
                               as a coverage gap so it is never mistaken for "clean".

Grouping: one finding per (rule, file, referenced value); every location where the value
is used becomes its own evidence record with a JSON pointer and line number.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from guardian.detectors._common import (
    SCHEMA_VERSION,
    first_seen_in,
    module_ids_for,
    now_utc,
    stable_id,
    validate,
)

DETECTOR = "guardian-d5-ci"
DETECTOR_VERSION = "1.0.0"
STAGE = "ci_workflow_policy"
_MAX_FILE_BYTES = 1024 * 1024
_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SHORT_SHA = re.compile(r"^[0-9a-fA-F]{7,39}$")
_VERSION_TAG = re.compile(r"^v?\d+(\.\d+){0,3}([-+][0-9A-Za-z.-]+)?$")
_DOCKER_DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
_GITHUB_OWNED = {"actions", "github"}


# ----------------------------------------------------------------------------- classification
def classify_uses(value: str) -> dict[str, Any]:
    """Describe a ``uses:`` value without any network lookup."""
    v = value.strip()
    if v.startswith(("./", ".\\")):
        return {"kind": "local"}
    if v.startswith("docker://"):
        image = v[len("docker://"):]
        if _DOCKER_DIGEST.search(image):
            return {"kind": "docker-digest", "image": image}
        return {"kind": "docker-mutable", "image": image}
    if "${{" in v:
        return {"kind": "expression"}
    if "@" not in v:
        return {"kind": "remote", "target": v, "ref": None, "ref_kind": "missing-ref",
                "owner": v.split("/", 1)[0]}
    target, ref = v.rsplit("@", 1)
    if _FULL_SHA.match(ref):
        ref_kind = "full-sha"
    elif _SHORT_SHA.match(ref):
        ref_kind = "short-sha"
    elif _VERSION_TAG.match(ref):
        ref_kind = "version-tag"
    else:
        ref_kind = "branch-or-other"
    return {"kind": "remote", "target": target, "ref": ref, "ref_kind": ref_kind, "owner": target.split("/", 1)[0],
            "reusable_workflow": "/.github/workflows/" in f"/{target}"}


# ----------------------------------------------------------------------------- yaml helpers
def _yaml():
    try:
        import yaml  # PyYAML

        return yaml
    except ImportError:
        return None


def _get(mapping, key: str):
    if mapping is None or getattr(mapping, "id", None) != "mapping":
        return None
    for key_node, value_node in mapping.value:
        if getattr(key_node, "value", None) == key:
            return value_node
    return None


def _items(mapping):
    if mapping is None or getattr(mapping, "id", None) != "mapping":
        return []
    return [(k.value, v) for k, v in mapping.value if getattr(k, "id", None) == "scalar"]


def _seq(node):
    return list(node.value) if node is not None and getattr(node, "id", None) == "sequence" else []


def _line(node) -> int:
    return node.start_mark.line + 1


def _esc(token: str) -> str:
    return str(token).replace("~", "~0").replace("/", "~1")


# ----------------------------------------------------------------------------- scanning
def _workflow_files(repo: Path) -> list[Path]:
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    root = repo.resolve()
    files = []
    for path in sorted(wf_dir.iterdir(), key=lambda p: p.name):
        if path.suffix.lower() not in {".yml", ".yaml"} or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue  # symlink escaping the repository: never read
        files.append(path)
    return files


_STAGE_FIELDS = ("stage", "status", "attempted", "tool", "tool_version", "reason", "completed_at",
                 "known_matches", "evidence_ids")


def scan_workflows(scan_id: str, repo_dir: str, run_dir: str | None = None) -> dict[str, Any]:
    """Run D5; returns ``{"stage", "stage_details", "findings", "evidence"}``.

    ``stage`` holds exactly the StageRecord fields (C's model forbids extras); file counts and
    notes are in ``stage_details``.
    """
    result = _scan_workflows(scan_id, repo_dir, run_dir)
    full = result["stage"]
    result["stage"] = validate("StageRecord", {k: full.get(k) for k in _STAGE_FIELDS})
    result["stage_details"] = {k: v for k, v in full.items() if k not in _STAGE_FIELDS}
    return result


def _scan_workflows(scan_id: str, repo_dir: str, run_dir: str | None = None) -> dict[str, Any]:
    repo = Path(repo_dir)
    run = Path(run_dir) if run_dir else None
    files = _workflow_files(repo)
    if not files:
        return {"stage": {"stage": STAGE, "status": "NOT_RUN", "attempted": False, "tool": DETECTOR,
                          "tool_version": DETECTOR_VERSION, "reason": "no .github/workflows/*.yml|yaml files found",
                          "files_found": 0, "files_scanned": 0, "files_failed": 0, "known_matches": None,
                          "completed_at": None, "evidence_ids": [], "notes": []},
                "findings": [], "evidence": []}
    yaml = _yaml()
    if yaml is None:
        return {"stage": {"stage": STAGE, "status": "UNAVAILABLE", "attempted": False, "tool": DETECTOR,
                          "tool_version": DETECTOR_VERSION, "reason": "PyYAML is not installed",
                          "files_found": len(files), "files_scanned": 0, "files_failed": 0,
                          "known_matches": None, "completed_at": None, "evidence_ids": [], "notes": []},
                "findings": [], "evidence": []}

    recorded_at = now_utc()
    provenance = first_seen_in(run)
    hits: dict[tuple[str, str, str], dict[str, Any]] = {}
    evidence: list[dict[str, Any]] = []
    notes: list[str] = []
    scanned = failed = 0
    no_permissions: list[str] = []

    for path in files:
        rel = path.relative_to(repo).as_posix()
        data = path.read_bytes() if path.stat().st_size <= _MAX_FILE_BYTES else None
        raw_rel, raw_sha = None, None
        if data is not None:
            raw_sha = hashlib.sha256(data).hexdigest()
            if run is not None:
                target = run / "raw" / "ci" / rel.replace("/", "__")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
                raw_rel = target.relative_to(run).as_posix()

        def add_evidence(pointer: str, line: int | None, value: Any, observation: str) -> str:
            eid = stable_id("ev", scan_id, "CI_CONFIG", rel, pointer, raw_sha)
            evidence.append({
                "schema_version": SCHEMA_VERSION, "scan_id": scan_id, "evidence_id": eid, "kind": "CI_CONFIG",
                "tool_name": DETECTOR, "tool_version": DETECTOR_VERSION, "source_path": rel,
                "json_pointer": pointer, "line_start": line, "line_end": line,
                "observed_value": value if not isinstance(value, str) else value[:200],
                "raw_artifact": raw_rel, "raw_sha256": raw_sha if raw_rel else None,
                "observation": observation, "recorded_at": recorded_at,
            })
            return eid

        def hit(rule: str, value: str, pointer: str, line: int | None, detail: dict[str, Any], observation: str) -> None:
            eid = add_evidence(pointer, line, value, observation)
            entry = hits.setdefault((rule, rel, value), {"rule": rule, "file": rel, "value": value,
                                                          "detail": detail, "pointers": [], "evidence_ids": []})
            entry["pointers"].append(pointer)
            entry["evidence_ids"].append(eid)

        try:
            if data is None:
                raise ValueError(f"file larger than {_MAX_FILE_BYTES} bytes")
            root = yaml.compose(data.decode("utf-8"), Loader=yaml.SafeLoader)
            if root is None or root.id != "mapping":
                raise ValueError("workflow is not a YAML mapping")
        except Exception as exc:  # noqa: BLE001 - any parse problem is a coverage gap
            failed += 1
            mark = getattr(exc, "problem_mark", None)
            line = mark.line + 1 if mark is not None else None
            reason = getattr(exc, "problem", None) or type(exc).__name__
            hit("D5-UNPARSED-WORKFLOW", rel, "", line, {"error": str(reason)[:200]},
                f"{rel} could not be parsed ({str(reason)[:120]}); its contents were not analysed")
            continue
        scanned += 1

        # permissions (workflow level)
        perms = _get(root, "permissions")
        if perms is None:
            no_permissions.append(rel)
        else:
            granted = _write_grants(perms)
            if granted:
                value = "write-all" if granted == ["write-all"] else ", ".join(f"{s}: write" for s in granted)
                hit("D5-WRITE-PERMISSIONS", f"workflow: {value}", "/permissions", _line(perms),
                    {"level": "workflow", "scopes": granted},
                    f"{rel} grants {value} to every job by default")

        for job_id, job in _items(_get(root, "jobs")):
            base = f"/jobs/{_esc(job_id)}"
            job_perms = _get(job, "permissions")
            if job_perms is not None and getattr(job_perms, "id", None) == "scalar" and job_perms.value == "write-all":
                hit("D5-WRITE-PERMISSIONS", f"job {job_id}: write-all", f"{base}/permissions", _line(job_perms),
                    {"level": "job", "job": job_id, "scopes": ["write-all"]},
                    f"{rel} job {job_id} grants write-all")
            reusable = _get(job, "uses")
            if reusable is not None and getattr(reusable, "id", None) == "scalar":
                _check_uses(hit, rel, reusable, f"{base}/uses", notes)
            for index, step in enumerate(_seq(_get(job, "steps"))):
                uses = _get(step, "uses")
                if uses is not None and getattr(uses, "id", None) == "scalar":
                    _check_uses(hit, rel, uses, f"{base}/steps/{index}/uses", notes)

    if no_permissions:
        notes.append(f"{len(no_permissions)} workflow(s) declare no top-level permissions; effective token "
                     f"permissions then depend on repository/organisation defaults, which are not visible: "
                     f"{', '.join(no_permissions)}")

    findings = [_finding(scan_id, h, provenance, run) for h in hits.values()]
    findings.sort(key=lambda f: (f["rule_id"], f["title"]))
    status = "COMPLETE" if failed == 0 else ("FAILED" if scanned == 0 else "PARTIAL")
    stage = {"stage": STAGE, "status": status, "attempted": True, "tool": DETECTOR, "tool_version": DETECTOR_VERSION,
             "reason": None if failed == 0 else f"{failed} of {len(files)} workflow file(s) could not be parsed",
             "files_found": len(files), "files_scanned": scanned, "files_failed": failed,
             "known_matches": len([f for f in findings if f["rule_id"] != "D5-UNPARSED-WORKFLOW"]),
             "completed_at": recorded_at, "evidence_ids": [], "notes": notes}
    return {"stage": stage, "findings": [validate("Finding", f) for f in findings],
            "evidence": [validate("Evidence", e) for e in evidence]}


def _write_grants(node) -> list[str]:
    if getattr(node, "id", None) == "scalar":
        return ["write-all"] if node.value == "write-all" else []
    return sorted(scope for scope, value in _items(node)
                  if getattr(value, "id", None) == "scalar" and value.value == "write")


def _check_uses(hit, rel: str, node, pointer: str, notes: list[str]) -> None:
    value = str(node.value)
    info = classify_uses(value)
    line = _line(node)
    if info["kind"] in {"local", "docker-digest"}:
        return
    if info["kind"] == "expression":
        notes.append(f"{rel}{pointer}: 'uses' contains an expression and was not evaluated")
        return
    if info["kind"] == "docker-mutable":
        hit("D5-UNPINNED-DOCKER-IMAGE", value, pointer, line, info,
            f"{rel} line {line}: container image {info['image']} is referenced without a digest")
        return
    if info["ref_kind"] == "full-sha":
        return
    hit("D5-UNPINNED-ACTION", value, pointer, line, info,
        f"{rel} line {line}: {value} uses a mutable reference ({info['ref_kind']})")


_RECOMMEND = {
    "D5-UNPINNED-ACTION": "Pin to the full 40-character commit SHA of a reviewed release (keep the tag as a comment) "
                          "and update pins deliberately.",
    "D5-UNPINNED-DOCKER-IMAGE": "Pin the container image by digest (image@sha256:...).",
    "D5-WRITE-PERMISSIONS": "Declare least-privilege permissions at workflow level (for example contents: read) and "
                            "grant write scopes only to the job that needs them.",
    "D5-UNPARSED-WORKFLOW": "Fix the workflow syntax or inspect the file manually; until then CI coverage is incomplete.",
}


def _finding(scan_id: str, h: dict[str, Any], provenance: str, run: Path | None) -> dict[str, Any]:
    rule, rel, value, detail = h["rule"], h["file"], h["value"], h["detail"]
    uncertainties = []
    if rule == "D5-UNPINNED-ACTION":
        owner = detail.get("owner", "")
        kind = "reusable workflow" if detail.get("reusable_workflow") else "action"
        title = f"Mutable {kind} reference {value} ({detail['ref_kind']}) in {rel}"
        description = (f"{rel} references the {kind} {detail['target']} at '{detail.get('ref') or '(no ref)'}', "
                       f"a {detail['ref_kind']} reference that its publisher can move after review.")
        uncertainties.append("A mutable reference is a configuration weakness, not evidence that the action is malicious.")
        if owner in _GITHUB_OWNED:
            uncertainties.append(f"Publisher '{owner}' is GitHub-owned; the reference is still mutable.")
    elif rule == "D5-UNPINNED-DOCKER-IMAGE":
        title = f"Container image without digest {value} in {rel}"
        description = f"{rel} runs the container image {detail['image']} by tag; the tag can point to new content."
        uncertainties.append("The image content itself was not inspected.")
    elif rule == "D5-WRITE-PERMISSIONS":
        title = f"Write permissions granted ({value}) in {rel}"
        description = f"{rel} grants {value}; any step or third-party action in scope can use that token access."
        uncertainties.append("Effective permissions also depend on repository and organisation settings.")
        uncertainties.append("Whether any step actually needs or misuses the access is not analysed.")
    else:
        title = f"Workflow could not be analysed: {rel}"
        description = f"{rel} could not be parsed: {detail.get('error')}. Its references and permissions are unknown."
        uncertainties.append("Contents of this workflow are unknown; absence of findings here means nothing.")
    if len(h["pointers"]) > 1:
        uncertainties.append(f"The same value is used at {len(h['pointers'])} locations in this file.")
    coverage_gap = rule == "D5-UNPARSED-WORKFLOW"
    return {
        "schema_version": SCHEMA_VERSION, "scan_id": scan_id,
        "finding_id": stable_id("fnd", scan_id, rule, rel, value),
        "finding_type": "COVERAGE_GAP" if coverage_gap else "CI_POLICY",
        "title": title, "description": description,
        "module_ids": module_ids_for(run, rel), "occurrence_ids": [],
        "advisory_ids": [], "advisory_urls": [], "rule_id": rule,
        "severity_label": None, "cvss_score": None, "priority": "NEEDS_REVIEW",
        "evidence_ids": h["evidence_ids"], "dependency_path_node_ids": [], "path_status": "NOT_APPLICABLE",
        "execution_stage": "CI", "execution_evidence": "NOT_ANALYZED" if coverage_gap else "POTENTIAL",
        "evidence_basis": "RULE_MATCH" if not coverage_gap else "UNKNOWN",
        "uncertainties": uncertainties, "recommendations": [_RECOMMEND[rule]],
        "classification": "COVERAGE_LIMITATION" if coverage_gap else "CONFIGURATION_WEAKNESS",
        "advisory_aliases": [], "first_seen_in": provenance, "advisory_as_of": None,
        "scanner_names": [DETECTOR],
    }
