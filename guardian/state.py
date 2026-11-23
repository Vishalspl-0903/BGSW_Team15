"""Run-folder persistence, offline run validation and the workflow state machine.

Owner: Role C.  Everything here is deterministic and works with no network,
no LLM and no LangGraph.

* ``validate_run_dir`` — schema + referential integrity for ``validate-run``.
* ``append_jsonl`` / ``write_json_atomic`` — durable artifact writes.
* ``EventLog`` — append-only ``events.jsonl`` with transition enforcement for
  the scan workflow and the per-finding remediation workflow (§9.6).
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from pydantic import ValidationError

from guardian.schemas import (
    RUN_FILE_MODELS,
    RUN_JSONL_MODELS,
    SCHEMA_VERSION,
    ActorType,
    ApprovalRecord,
    EdgeResolution,
    Event,
    Evidence,
    EvidenceKind,
    FindingsFile,
    GraphBundle,
    ModuleIndex,
    ProposalsFile,
    Relationship,
    Report,
    RiskFile,
    ScanMetadata,
    StageStatus,
    ValidationResult,
    WorkflowState,
    utc_now,
)

# ---------------------------------------------------------------------------
# Durable writes
# ---------------------------------------------------------------------------

_APPEND_LOCK = threading.Lock()


def write_json_atomic(path: str | Path, payload: Any) -> Path:
    """Write JSON via temp file + fsync + rename so readers never see half a file."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def append_jsonl(path: str | Path, record: dict[str, Any]) -> None:
    """Append one JSON line and fsync before returning (persist-before-display)."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    with _APPEND_LOCK, target.open("ab") as stream:
        stream.write(line.encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    out = []
    with Path(path).open("r", encoding="utf-8") as stream:
        for number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{Path(path).name}:{number}: invalid JSON: {exc.msg}") from exc
    return out


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_evidence_index(run_dir: str | Path) -> dict[str, Evidence]:
    path = Path(run_dir) / "evidence.jsonl"
    if not path.exists():
        return {}
    index: dict[str, Evidence] = {}
    for row in read_jsonl(path):
        ev = Evidence.model_validate(row)
        index[ev.evidence_id] = ev
    return index


def safe_run_path(run_dir: str | Path, relative: str) -> Path:
    """Resolve a run-relative path, refusing anything that escapes ``run_dir``."""
    root = Path(run_dir).resolve()
    candidate = (root / relative).resolve()
    candidate.relative_to(root)  # raises ValueError on escape
    return candidate


# ---------------------------------------------------------------------------
# validate-run
# ---------------------------------------------------------------------------


@dataclass
class RunCheck:
    run_dir: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _fmt(exc: ValidationError, label: str) -> list[str]:
    out = []
    for err in exc.errors()[:20]:
        loc = ".".join(str(p) for p in err.get("loc", ()))
        out.append(f"{label}: {loc or '<root>'}: {err.get('msg')}")
    return out


_EDGE_EVIDENCE_KINDS = {EvidenceKind.LOCKFILE, EvidenceKind.SBOM, EvidenceKind.MANIFEST}


def validate_run_dir(run_dir: str | Path) -> RunCheck:
    """Schema + referential integrity of a run folder, fully offline.

    Passing does NOT mean scan stages succeeded (§21.4): a valid PARTIAL run passes.
    """
    root = Path(run_dir)
    check = RunCheck(run_dir=root)
    if not root.is_dir():
        check.errors.append(f"run directory not found: {root.as_posix()}")
        return check

    docs: dict[str, Any] = {}
    for name, model in RUN_FILE_MODELS.items():
        path = root / name
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            check.errors.append(f"{name}: unreadable JSON: {exc}")
            continue
        try:
            docs[name] = model.model_validate(raw)
            check.checked.append(name)
        except ValidationError as exc:
            check.errors.extend(_fmt(exc, name))

    lines: dict[str, list[Any]] = {}
    for name, model in RUN_JSONL_MODELS.items():
        path = root / name
        if not path.exists():
            continue
        try:
            rows = read_jsonl(path)
        except (OSError, ValueError) as exc:
            check.errors.append(str(exc))
            continue
        parsed = []
        for number, row in enumerate(rows, start=1):
            try:
                parsed.append(model.model_validate(row))
            except ValidationError as exc:
                check.errors.extend(_fmt(exc, f"{name}:{number}"))
        lines[name] = parsed
        check.checked.append(name)

    if "metadata.json" not in docs:
        if not (root / "metadata.json").exists():
            check.errors.append("metadata.json is required")
        return check
    meta: ScanMetadata = docs["metadata.json"]
    scan_id = meta.scan_id

    # --- one scan_id across every artifact (no cross-linked runs) ---
    for name, doc in docs.items():
        sid = getattr(doc, "scan_id", None)
        if sid is not None and sid != scan_id:
            check.errors.append(f"{name}: scan_id {sid!r} conflicts with metadata scan_id {scan_id!r}")
    for name, rows in lines.items():
        for row in rows:
            if row.scan_id != scan_id:
                ident = getattr(row, "evidence_id", None) or getattr(row, "event_id", "?")
                check.errors.append(f"{name}: {ident} scan_id {row.scan_id!r} conflicts with {scan_id!r}")

    # --- evidence ledger ---
    evidence: dict[str, Evidence] = {}
    for ev in lines.get("evidence.jsonl", []):
        if ev.evidence_id in evidence:
            check.errors.append(f"evidence.jsonl: duplicate evidence_id {ev.evidence_id} (ledger is append-only)")
        evidence[ev.evidence_id] = ev
    for ev in evidence.values():
        if ev.supersedes is not None and ev.supersedes not in evidence:
            check.errors.append(f"evidence {ev.evidence_id} supersedes unknown {ev.supersedes}")
        if ev.raw_artifact is not None:
            try:
                raw_path = safe_run_path(root, ev.raw_artifact)
            except ValueError:
                check.errors.append(f"evidence {ev.evidence_id}: raw_artifact escapes run folder")
                continue
            if not raw_path.is_file():
                check.errors.append(f"evidence {ev.evidence_id}: raw_artifact {ev.raw_artifact} does not exist")
            elif sha256_file(raw_path) != ev.raw_sha256:
                check.errors.append(f"evidence {ev.evidence_id}: raw_sha256 does not match {ev.raw_artifact}")

    def need_evidence(owner: str, ids: Iterable[str]) -> None:
        for eid in ids:
            if eid not in evidence:
                check.errors.append(f"{owner} references unknown evidence {eid}")

    # --- stage honesty: a COMPLETE stage must have produced its artifact ---
    stage_artifacts = {"inventory": "module_index.json", "graph": "graph.json"}
    for stage, artifact in stage_artifacts.items():
        if meta.stage_statuses.get(stage) == StageStatus.COMPLETE and not (root / artifact).exists():
            check.errors.append(f"metadata says stage {stage} COMPLETE but {artifact} is missing")
    if (root / "graph.json").exists() and not (root / "evidence.jsonl").exists():
        check.errors.append("graph.json exists but evidence.jsonl is missing")

    # --- module index vs graph ---
    module_index: ModuleIndex | None = docs.get("module_index.json")
    graph: GraphBundle | None = docs.get("graph.json")
    module_ids: set[str] = set()
    nodes: set[str] = set()
    occurrences: set[str] = set()
    if module_index is not None:
        module_ids = {m.module_id for m in module_index.modules}
    if graph is not None:
        check.errors.extend(graph.integrity_errors())
        g_mods = {m.module_id: m for m in graph.modules}
        module_ids |= set(g_mods)
        occurrences = {c.occurrence_id for c in graph.components}
        nodes = set(g_mods) | occurrences
        if module_index is not None:
            idx = {m.module_id: m for m in module_index.modules}
            if set(idx) != set(g_mods):
                check.errors.append(
                    f"graph.modules {sorted(g_mods)} do not match module_index.json {sorted(idx)}"
                )
        for comp in graph.components:
            need_evidence(f"component {comp.occurrence_id}", comp.evidence_ids)
        for edge in graph.edges:
            need_evidence(f"edge {edge.edge_id}", edge.evidence_ids)
            if edge.resolution == EdgeResolution.OBSERVED and edge.relationship == Relationship.DEPENDS_ON:
                kinds = {evidence[e].kind for e in edge.evidence_ids if e in evidence}
                if EvidenceKind.MODEL_OUTPUT in kinds:
                    check.errors.append(f"edge {edge.edge_id}: OBSERVED edge cites MODEL_OUTPUT evidence")
                if kinds and not kinds & _EDGE_EVIDENCE_KINDS:
                    check.errors.append(
                        f"edge {edge.edge_id}: OBSERVED DEPENDS_ON needs LOCKFILE/SBOM/MANIFEST evidence"
                    )

    # --- findings ---
    findings: FindingsFile | None = docs.get("findings.json")
    finding_ids: set[str] = set()
    if findings is not None:
        finding_ids = {f.finding_id for f in findings.findings}
        for f in findings.findings:
            need_evidence(f"finding {f.finding_id}", f.evidence_ids)
            for mid in f.module_ids:
                if module_ids and mid not in module_ids:
                    check.errors.append(f"finding {f.finding_id} references unknown module {mid}")
            for oid in f.occurrence_ids:
                if graph is not None and oid not in occurrences:
                    check.errors.append(f"finding {f.finding_id} references unknown occurrence {oid}")
            for nid in f.dependency_path_node_ids:
                if graph is not None and nid not in nodes:
                    check.errors.append(f"finding {f.finding_id} path references unknown node {nid}")
            if (f.occurrence_ids or f.module_ids) and graph is None and module_index is None:
                check.errors.append(f"finding {f.finding_id} references graph IDs but no graph/module index exists")

    # --- events ---
    events: list[Event] = lines.get("events.jsonl", [])
    event_ids: set[str] = set()
    for ev in events:
        if ev.event_id in event_ids:
            check.errors.append(f"events.jsonl: duplicate event_id {ev.event_id}")
        event_ids.add(ev.event_id)
        need_evidence(f"event {ev.event_id}", ev.evidence_ids)
    timestamps = [e.timestamp for e in events]
    if timestamps != sorted(timestamps):
        check.errors.append("events.jsonl: timestamps are not monotonically non-decreasing")

    # --- risk ---
    risk: RiskFile | None = docs.get("risk.json")
    claim_ids: set[str] = set()
    if risk is not None:
        claim_ids = {c.claim_id for c in risk.claims}
        for a in risk.assessments:
            if a.finding_id not in finding_ids:
                check.errors.append(f"risk assessment references unknown finding {a.finding_id}")
            need_evidence(f"risk assessment {a.finding_id}", a.evidence_ids)
        for c in risk.claims:
            if c.validated:
                need_evidence(f"claim {c.claim_id}", c.evidence_ids)

    # --- proposals / validation ---
    proposals: ProposalsFile | None = docs.get("proposals.json")
    proposal_ids: set[str] = set()
    if proposals is not None:
        proposal_ids = {p.proposal_id for p in proposals.proposals}
        for p in proposals.proposals:
            for fid in p.finding_ids:
                if fid not in finding_ids:
                    check.errors.append(f"proposal {p.proposal_id} references unknown finding {fid}")
            if module_ids and p.target_module_id not in module_ids:
                check.errors.append(f"proposal {p.proposal_id} targets unknown module {p.target_module_id}")
            need_evidence(f"proposal {p.proposal_id}", p.evidence_ids)
            if p.approval_event_id is not None and p.approval_event_id not in event_ids:
                check.errors.append(f"proposal {p.proposal_id} references unknown approval event")
        for a in proposals.audit_results:
            need_evidence(f"audit {a.audit_result_id}", a.evidence_ids)
    validation: ValidationResult | None = docs.get("validation.json")
    if validation is not None:
        if validation.proposal_id not in proposal_ids:
            check.errors.append(f"validation.json references unknown proposal {validation.proposal_id}")
        if validation.approval_event_id is not None and validation.approval_event_id not in event_ids:
            check.errors.append("validation.json references unknown approval event")
        for cmd in validation.commands:
            if cmd.log_evidence_id is not None:
                need_evidence("validation command", [cmd.log_evidence_id])

    # --- report ---
    report: Report | None = docs.get("report.json")
    if report is not None:
        for fid in report.finding_ids:
            if fid not in finding_ids:
                check.errors.append(f"report references unknown finding {fid}")
        for cid in report.claim_ids:
            if cid not in claim_ids:
                check.errors.append(f"report references unknown claim {cid}")
        for pid in report.proposal_ids:
            if pid not in proposal_ids:
                check.errors.append(f"report references unknown proposal {pid}")
        for label, rel in report.artifact_paths.items():
            try:
                if not safe_run_path(root, rel).exists():
                    check.errors.append(f"report artifact {label} -> {rel} does not exist")
            except ValueError:
                check.errors.append(f"report artifact {label} escapes run folder")
        if report.metadata.to_json_dict() != meta.to_json_dict():
            check.warnings.append("report.metadata differs from metadata.json (report may be stale)")

    for name in docs:
        if getattr(docs[name], "schema_version", SCHEMA_VERSION) != SCHEMA_VERSION:
            check.warnings.append(f"{name}: schema_version differs from current {SCHEMA_VERSION}")
    return check


# ---------------------------------------------------------------------------
# Workflow state machine (§9.6)
# ---------------------------------------------------------------------------

S = WorkflowState

SCAN_TRANSITIONS: dict[WorkflowState | None, frozenset[WorkflowState]] = {
    None: frozenset({S.CREATED}),
    S.CREATED: frozenset({S.ACQUIRING, S.FAILED, S.BLOCKED}),
    S.ACQUIRING: frozenset({S.INDEXING, S.FAILED, S.BLOCKED}),
    S.INDEXING: frozenset({S.INVENTORY_READY, S.FAILED, S.BLOCKED}),
    S.INVENTORY_READY: frozenset({S.DETECTING, S.FAILED, S.BLOCKED}),
    S.DETECTING: frozenset({S.FINDINGS_READY, S.FAILED, S.BLOCKED}),
    S.FINDINGS_READY: frozenset({S.ANALYZING, S.FAILED, S.BLOCKED}),
    S.ANALYZING: frozenset({S.ANALYZED, S.FAILED, S.BLOCKED}),
    S.ANALYZED: frozenset(),
    S.FAILED: frozenset(),
    S.BLOCKED: frozenset(),
}

# Per-finding remediation workflow; starts from an ANALYZED scan.
REMEDIATION_TRANSITIONS: dict[WorkflowState | None, frozenset[WorkflowState]] = {
    None: frozenset({S.PROPOSING}),
    S.PROPOSING: frozenset({S.AUDITING, S.BLOCKED, S.FAILED, S.REJECTED}),
    S.AUDITING: frozenset({S.REVIEW_PENDING, S.REJECTED, S.BLOCKED, S.FAILED}),
    S.REVIEW_PENDING: frozenset({S.APPROVED, S.REJECTED, S.BLOCKED}),
    S.APPROVED: frozenset({S.VALIDATING, S.BLOCKED, S.REJECTED}),
    S.VALIDATING: frozenset({S.VERIFIED, S.FAILED, S.BLOCKED, S.INCONCLUSIVE}),
    S.VERIFIED: frozenset(),
    S.REJECTED: frozenset(),
    S.FAILED: frozenset(),
    S.BLOCKED: frozenset(),
    S.INCONCLUSIVE: frozenset(),
}


class TransitionError(RuntimeError):
    """A requested state transition is not permitted; nothing was persisted."""


def scan_workflow_id(scan_id: str) -> str:
    return f"scan:{scan_id}"


def remediation_workflow_id(proposal_id: str) -> str:
    return f"remediation:{proposal_id}"


class EventLog:
    """Append-only ``events.jsonl``; transitions are validated before persisting."""

    def __init__(self, run_dir: str | Path, scan_id: str) -> None:
        self.run_dir = Path(run_dir)
        self.path = self.run_dir / "events.jsonl"
        self.scan_id = scan_id

    # -- reading ---------------------------------------------------------
    def events(self) -> list[Event]:
        if not self.path.exists():
            return []
        return [Event.model_validate(r) for r in read_jsonl(self.path)]

    def get(self, event_id: str) -> Event | None:
        return next((e for e in self.events() if e.event_id == event_id), None)

    def current_state(self, workflow_id: str) -> WorkflowState | None:
        state = None
        for ev in self.events():
            if ev.workflow_id == workflow_id and ev.next_state is not None:
                state = ev.next_state
        return state

    # -- writing ---------------------------------------------------------
    def record(
        self,
        *,
        event_type: str,
        actor_type: ActorType,
        actor_label: str,
        message: str,
        workflow_id: str | None = None,
        previous_state: WorkflowState | None = None,
        next_state: WorkflowState | None = None,
        related_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        approval: ApprovalRecord | None = None,
    ) -> Event:
        event = Event(
            schema_version=SCHEMA_VERSION,
            scan_id=self.scan_id,
            event_id=f"evt:{uuid.uuid4().hex}",
            timestamp=utc_now(),
            actor_type=actor_type,
            actor_label=actor_label,
            event_type=event_type,
            previous_state=previous_state,
            next_state=next_state,
            related_ids=list(related_ids or []),
            evidence_ids=list(evidence_ids or []),
            message=message,
            workflow_id=workflow_id,
            approval=approval,
        )
        append_jsonl(self.path, event.to_json_dict())
        return event

    def transition(
        self,
        workflow_id: str,
        next_state: WorkflowState,
        *,
        actor_type: ActorType = ActorType.SYSTEM,
        actor_label: str = "guardian",
        message: str,
        event_type: str = "STATE_TRANSITION",
        related_ids: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        approval: ApprovalRecord | None = None,
        expected_state: WorkflowState | None | str = "__current__",
    ) -> Event:
        table = SCAN_TRANSITIONS if workflow_id.startswith("scan:") else REMEDIATION_TRANSITIONS
        current = self.current_state(workflow_id)
        if expected_state != "__current__" and expected_state != current:
            raise TransitionError(
                f"{workflow_id}: expected state {expected_state} but log says {current} (stale request)"
            )
        allowed = table.get(current, frozenset())
        if next_state not in allowed:
            raise TransitionError(
                f"{workflow_id}: transition {current.value if current else None} -> {next_state.value} "
                "is not permitted"
            )
        if actor_type == ActorType.LLM:
            raise TransitionError("an LLM actor cannot perform workflow transitions")
        if next_state == S.APPROVED:
            if actor_type != ActorType.HUMAN or approval is None:
                raise TransitionError("APPROVED requires a HUMAN actor with an approval record")
        return self.record(
            event_type=event_type, actor_type=actor_type, actor_label=actor_label, message=message,
            workflow_id=workflow_id, previous_state=current, next_state=next_state,
            related_ids=related_ids, evidence_ids=evidence_ids, approval=approval,
        )
