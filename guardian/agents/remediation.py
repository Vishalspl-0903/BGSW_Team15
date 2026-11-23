"""Per-finding remediation workflow (§4 "Remediation workflow", §9.6, §22).

    PROPOSING -> AUDITING -> REVIEW_PENDING -(human)-> APPROVED -> VALIDATING
                     |             |                              -> VERIFIED/FAILED/BLOCKED/INCONCLUSIVE
                 BLOCKED       REJECTED

Explicit Python state machine over ``events.jsonl`` (no LangGraph).  Every
transition is persisted before the function returns.  Model roles can only
produce proposals and critiques; the Guard decides REVIEW_PENDING; only a
HUMAN decision reaches APPROVED; only a verified, fresh, hash-bound approval
reaches VALIDATING.  No code here merges, publishes, deploys or runs shell.
"""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from guardian import llm
from guardian.agents import critic as critic_role
from guardian.agents import remediator
from guardian.guard import check_approval, check_proposal, load_policy
from guardian.schemas import (
    SCHEMA_VERSION,
    ActorType,
    ApprovalDecision,
    ApprovalRecord,
    AuditVerdict,
    Evidence,
    Finding,
    FindingsFile,
    FixAuditResult,
    GraphBundle,
    ModuleIndex,
    ProjectModule,
    Proposal,
    ProposalsFile,
    ProposalStatus,
    ScanMetadata,
    ValidationResult,
    ValidationStatus,
    WorkflowState,
    proposal_digest,
    utc_now,
)
from guardian.state import (
    EventLog,
    TransitionError,
    load_evidence_index,
    remediation_workflow_id,
    scan_workflow_id,
    sha256_file,
    write_json_atomic,
)

S = WorkflowState


class RemediationError(RuntimeError):
    pass


class ApprovalDenied(RuntimeError):
    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons) or "approval denied")
        self.reasons = reasons


@dataclass
class RunContext:
    run_dir: Path
    metadata: ScanMetadata
    modules: dict[str, ProjectModule]
    findings: dict[str, Finding]
    evidence: dict[str, Evidence]
    proposals: ProposalsFile
    policy: dict
    log: EventLog

    @property
    def repo_dir(self) -> Path:
        return self.run_dir / "repo"

    def proposal(self, proposal_id: str) -> Proposal:
        for p in self.proposals.proposals:
            if p.proposal_id == proposal_id:
                return p
        raise RemediationError(f"unknown proposal {proposal_id}")

    def audit_for(self, proposal: Proposal) -> FixAuditResult | None:
        return next((a for a in self.proposals.audit_results
                     if a.audit_result_id == proposal.audit_result_id), None)

    def save_proposal(self, proposal: Proposal, audit: FixAuditResult | None = None) -> None:
        props = [p for p in self.proposals.proposals if p.proposal_id != proposal.proposal_id] + [proposal]
        audits = [a for a in self.proposals.audit_results
                  if audit is None or a.audit_result_id != audit.audit_result_id]
        if audit is not None:
            audits.append(audit)
        self.proposals = ProposalsFile(schema_version=SCHEMA_VERSION, scan_id=self.metadata.scan_id,
                                       proposals=props, audit_results=audits)
        write_json_atomic(self.run_dir / "proposals.json", self.proposals.to_json_dict())


def load_context(run_dir: str | Path, policy: dict | None = None) -> RunContext:
    root = Path(run_dir)

    def read(name: str):
        return json.loads((root / name).read_text(encoding="utf-8"))

    meta = ScanMetadata.model_validate(read("metadata.json"))
    modules: dict[str, ProjectModule] = {}
    if (root / "graph.json").exists():
        modules = {m.module_id: m for m in GraphBundle.model_validate(read("graph.json")).modules}
    elif (root / "module_index.json").exists():
        modules = {m.module_id: m for m in ModuleIndex.model_validate(read("module_index.json")).modules}
    findings = {}
    if (root / "findings.json").exists():
        findings = {f.finding_id: f for f in FindingsFile.model_validate(read("findings.json")).findings}
    proposals = (ProposalsFile.model_validate(read("proposals.json")) if (root / "proposals.json").exists()
                 else ProposalsFile(schema_version=SCHEMA_VERSION, scan_id=meta.scan_id, proposals=[],
                                    audit_results=[]))
    return RunContext(root, meta, modules, findings, load_evidence_index(root), proposals,
                      policy or load_policy(), EventLog(root, meta.scan_id))


_STATUS_FOR_STATE = {
    S.REVIEW_PENDING: ProposalStatus.NEEDS_REVIEW, S.REJECTED: ProposalStatus.REJECTED,
    S.BLOCKED: ProposalStatus.BLOCKED, S.APPROVED: ProposalStatus.APPROVED,
    S.VALIDATING: ProposalStatus.VALIDATING, S.VERIFIED: ProposalStatus.VERIFIED,
    S.FAILED: ProposalStatus.FAILED, S.INCONCLUSIVE: ProposalStatus.FAILED,
}


def _set_status(ctx: RunContext, proposal: Proposal, state: WorkflowState, **extra) -> Proposal:
    updated = Proposal.model_validate({**proposal.to_json_dict(), **extra,
                                       "status": _STATUS_FOR_STATE.get(state, proposal.status).value})
    ctx.save_proposal(updated)
    return updated


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


def start(run_dir: str | Path, finding_id: str, *, human_candidate: dict | None = None,
          config: llm.LLMConfig | None = None, transport: llm.Transport | None = None) -> Proposal:
    ctx = load_context(run_dir)
    if ctx.log.current_state(scan_workflow_id(ctx.metadata.scan_id)) != S.ANALYZED:
        raise RemediationError("remediation starts only from an ANALYZED scan")
    finding = ctx.findings.get(finding_id)
    if finding is None:
        raise RemediationError(f"unknown finding {finding_id}")
    if not finding.evidence_ids or any(e not in ctx.evidence for e in finding.evidence_ids):
        raise RemediationError("finding is not evidence-backed; remediation refused")
    limit = int(ctx.policy["remediation"].get("max_proposals_per_finding", 3))
    existing = [p for p in ctx.proposals.proposals if finding_id in p.finding_ids]
    if len(existing) >= limit:
        raise RemediationError(f"proposal limit reached for {finding_id} ({limit}); escalate to a human")
    module_id = finding.module_ids[0] if finding.module_ids else None
    module = ctx.modules.get(module_id or "")
    if module is None:
        raise RemediationError("finding has no known owning module")
    proposal, source = remediator.propose(finding, module, ctx.repo_dir, human_candidate=human_candidate,
                                          run_dir=ctx.run_dir, config=config, transport=transport)
    if any(p.proposal_id == proposal.proposal_id for p in existing):
        raise RemediationError(f"identical proposal {proposal.proposal_id} already exists")
    wf = remediation_workflow_id(proposal.proposal_id)
    ctx.log.transition(wf, S.PROPOSING, message=f"proposal created by {source} for {finding_id}",
                       related_ids=[proposal.proposal_id, finding_id], evidence_ids=proposal.evidence_ids)
    ctx.save_proposal(proposal)
    return proposal


Auditor = Callable[[Proposal, str], FixAuditResult]


def _default_auditor() -> Auditor | None:
    """B's static candidate audit, if merged (requested signature, see PR notes)."""
    try:
        module = importlib.import_module("guardian.fixaudit.static_audit")
    except ImportError:
        return None
    return getattr(module, "audit_candidate", None)


def audit(run_dir: str | Path, proposal_id: str, *, auditor: Auditor | None = None) -> FixAuditResult | None:
    ctx = load_context(run_dir)
    proposal = ctx.proposal(proposal_id)
    wf = remediation_workflow_id(proposal_id)
    fn = auditor or _default_auditor()
    if fn is None:
        ctx.log.transition(wf, S.BLOCKED, message="candidate audit unavailable: fail closed (no automatic patch)",
                           event_type="GUARD_BLOCK", related_ids=[proposal_id])
        _set_status(ctx, proposal, S.BLOCKED)
        return None
    try:
        result = FixAuditResult.model_validate(fn(proposal, str(ctx.run_dir)))
    except Exception as exc:  # noqa: BLE001 - auditor failure must fail closed, visibly
        ctx.log.transition(wf, S.BLOCKED, message=f"candidate audit failed: {type(exc).__name__}",
                           event_type="GUARD_BLOCK", related_ids=[proposal_id])
        _set_status(ctx, proposal, S.BLOCKED)
        return None
    if result.proposal_id != proposal_id:
        ctx.log.transition(wf, S.BLOCKED, message="audit result is for a different proposal",
                           event_type="GUARD_BLOCK", related_ids=[proposal_id])
        _set_status(ctx, proposal, S.BLOCKED)
        return None
    updated = Proposal.model_validate({**proposal.to_json_dict(), "status": "AUDITED",
                                       "audit_result_id": result.audit_result_id})
    ctx.save_proposal(updated, result)
    ctx.log.transition(wf, S.AUDITING, actor_type=ActorType.TOOL, actor_label="fix-auditor",
                       message=f"candidate audit verdict {result.verdict.value} (ALLOW_REVIEW is not 'safe')",
                       related_ids=[proposal_id, result.audit_result_id], evidence_ids=[
                           e for e in result.evidence_ids if e in ctx.evidence])
    return result


def review(run_dir: str | Path, proposal_id: str, *, config: llm.LLMConfig | None = None,
           transport: llm.Transport | None = None) -> tuple[WorkflowState, list[str]]:
    ctx = load_context(run_dir)
    proposal = ctx.proposal(proposal_id)
    wf = remediation_workflow_id(proposal_id)
    if ctx.log.current_state(wf) != S.AUDITING:
        raise TransitionError(f"{wf}: review requires AUDITING, found {ctx.log.current_state(wf)}")
    audit_result = ctx.audit_for(proposal)
    findings = [ctx.findings[f] for f in proposal.finding_ids if f in ctx.findings]
    crit = critic_role.review(proposal, findings, audit_result, run_dir=ctx.run_dir, config=config,
                              transport=transport)
    if crit.verdict is not None:
        ctx.log.record(event_type="CRITIC_REVIEW", actor_type=ActorType.LLM, actor_label="critic",
                       workflow_id=wf, related_ids=[proposal_id],
                       message=f"critic verdict {crit.verdict}: {'; '.join(crit.concerns)[:500]}")
    decision = check_proposal(proposal, findings=ctx.findings, evidence_index=ctx.evidence,
                              modules=ctx.modules, repo_dir=ctx.repo_dir, audit=audit_result,
                              critic_verdict=crit.verdict, policy=ctx.policy)
    reasons = [f"{c.name}: {c.detail}" for c in decision.failures] + decision.notes
    ctx.log.transition(wf, decision.next_state, event_type="GUARD_DECISION", related_ids=[proposal_id],
                       message=f"guard: {decision.summary()}" + (f" | notes: {'; '.join(decision.notes)}"
                                                                 if decision.notes else ""))
    _set_status(ctx, proposal, decision.next_state)
    return decision.next_state, reasons


def decide(run_dir: str | Path, proposal_id: str, *, decision: str, reviewer_label: str, reviewer_role: str,
           confirm_digest: str, now: datetime | None = None) -> ApprovalRecord:
    """Record a HUMAN decision.  ``confirm_digest`` must be a prefix (>=12 hex) of the
    proposal digest shown to the reviewer, binding the decision to exact content."""
    ctx = load_context(run_dir)
    proposal = ctx.proposal(proposal_id)
    wf = remediation_workflow_id(proposal_id)
    dec = ApprovalDecision(decision.upper())
    digest = proposal_digest(proposal)
    if len(confirm_digest) < 12 or not digest.startswith(confirm_digest.lower()):
        raise ApprovalDenied(["confirm_digest does not match the current proposal digest (stale or wrong proposal)"])
    state = ctx.log.current_state(wf)
    audit_result = ctx.audit_for(proposal)
    if dec == ApprovalDecision.APPROVE:
        if state != S.REVIEW_PENDING:
            raise ApprovalDenied([f"proposal is {state.value if state else None}, not REVIEW_PENDING"])
        if audit_result is None or audit_result.verdict != AuditVerdict.ALLOW_REVIEW:
            raise ApprovalDenied(["audit verdict is not ALLOW_REVIEW; override is not permitted by policy"])
    now = now or datetime.now(timezone.utc)
    ttl = int(ctx.policy["remediation"].get("approval_ttl_minutes", 120))
    stamp = now.isoformat().replace("+00:00", "Z")
    prior = proposal.approval_event_id if dec == ApprovalDecision.REVOKE else None
    if dec == ApprovalDecision.REVOKE and prior is None:
        raise ApprovalDenied(["nothing to revoke"])
    lock = next(iter(ctx.modules[proposal.target_module_id].lockfiles), None) \
        if proposal.target_module_id in ctx.modules else None
    lock_sha = sha256_file(ctx.repo_dir / lock) if lock and (ctx.repo_dir / lock).is_file() else None
    record = ApprovalRecord(
        decision=dec, reviewer_label=reviewer_label, reviewer_role=reviewer_role, scan_id=ctx.metadata.scan_id,
        proposal_id=proposal_id, proposal_sha256=digest,
        audit_result_id=audit_result.audit_result_id if audit_result else None,
        commit_sha=ctx.metadata.commit_sha, lockfile_sha256=lock_sha,
        policy_version=int(ctx.policy["policy_version"]), decided_at=stamp,
        expires_at=(now + timedelta(minutes=ttl)).isoformat().replace("+00:00", "Z")
        if dec == ApprovalDecision.APPROVE else None,
        revokes_event_id=prior,
    )
    target = {ApprovalDecision.APPROVE: S.APPROVED, ApprovalDecision.REJECT: S.REJECTED,
              ApprovalDecision.REVOKE: S.BLOCKED}[dec]
    msg = {ApprovalDecision.APPROVE: "approved for sandbox validation only (not merge/publish)",
           ApprovalDecision.REJECT: "rejected by human reviewer",
           ApprovalDecision.REVOKE: "approval revoked by human reviewer"}[dec]
    event = ctx.log.transition(wf, target, actor_type=ActorType.HUMAN, actor_label=reviewer_label,
                               event_type=f"HUMAN_{dec.value}", message=msg, approval=record,
                               related_ids=[proposal_id] + ([record.audit_result_id] if record.audit_result_id
                                                            else []))
    extra = {"approval_event_id": event.event_id} if dec == ApprovalDecision.APPROVE else {}
    _set_status(ctx, proposal, target, **extra)
    return record


def verify_approval(run_dir: str | Path, proposal_id: str, approval_event_id: str | None, *,
                    now: datetime | None = None) -> ApprovalRecord:
    """Read-only approval check for A's validator.  Raises ``ApprovalDenied``."""
    ctx = load_context(run_dir)
    proposal = ctx.proposal(proposal_id)
    events = ctx.log.events()
    state = ctx.log.current_state(remediation_workflow_id(proposal_id))
    decision = check_approval(approval_event_id, proposal=proposal, audit=ctx.audit_for(proposal),
                              events=events, policy=ctx.policy, workflow_state=state, now=now)
    if not decision.allowed:
        raise ApprovalDenied([f"{c.name}: {c.detail}" for c in decision.failures])
    event = next(e for e in events if e.event_id == approval_event_id)
    if event.approval is None:  # pragma: no cover - check_approval already enforces this
        raise ApprovalDenied(["approval record missing"])
    return event.approval


def authorize_validation(run_dir: str | Path, proposal_id: str, approval_event_id: str | None, *,
                         now: datetime | None = None) -> ApprovalRecord:
    """Verify approval, then persist APPROVED -> VALIDATING.  Denials are persisted too."""
    ctx = load_context(run_dir)
    wf = remediation_workflow_id(proposal_id)
    try:
        record = verify_approval(run_dir, proposal_id, approval_event_id, now=now)
    except ApprovalDenied as denied:
        state = ctx.log.current_state(wf)
        if state == S.APPROVED:
            ctx.log.transition(wf, S.BLOCKED, event_type="GUARD_BLOCK", related_ids=[proposal_id],
                               message=f"Validation requires fresh approval: {denied}")
            _set_status(ctx, ctx.proposal(proposal_id), S.BLOCKED)
        else:
            ctx.log.record(event_type="GUARD_DENY", actor_type=ActorType.SYSTEM, actor_label="guard",
                           workflow_id=wf, related_ids=[proposal_id],
                           message=f"validation denied: {denied}")
        raise
    ctx.log.transition(wf, S.VALIDATING, related_ids=[proposal_id, approval_event_id or ""],
                       message="approval verified (fresh, human, hash-bound); sandbox validation may start")
    _set_status(ctx, ctx.proposal(proposal_id), S.VALIDATING)
    return record


Validator = Callable[[str, str, str, str], ValidationResult]

_STATE_FOR_VALIDATION = {
    ValidationStatus.PASS: S.VERIFIED, ValidationStatus.FAILED: S.FAILED,
    ValidationStatus.BLOCKED: S.BLOCKED, ValidationStatus.INCONCLUSIVE: S.INCONCLUSIVE,
    ValidationStatus.NOT_RUN: S.BLOCKED,
}


def validate(run_dir: str | Path, proposal_id: str, approval_event_id: str | None, *,
             validator: Validator | None = None, now: datetime | None = None) -> ValidationResult:
    """No approval -> no validator call.  A's validator is the only thing that patches a worktree."""
    authorize_validation(run_dir, proposal_id, approval_event_id, now=now)
    ctx = load_context(run_dir)
    wf = remediation_workflow_id(proposal_id)
    started = utc_now()
    if validator is None:
        from guardian.validator import validate_approved_proposal as validator  # A's public signature
    try:
        result = ValidationResult.model_validate(
            validator(ctx.metadata.scan_id, proposal_id, approval_event_id or "", str(ctx.run_dir)))
    except Exception as exc:  # noqa: BLE001 - validator outages are recorded, never hidden
        result = ValidationResult(
            schema_version=SCHEMA_VERSION, scan_id=ctx.metadata.scan_id, proposal_id=proposal_id,
            worktree_id=None, approval_event_id=approval_event_id, status=ValidationStatus.BLOCKED, commands=[],
            build_passed=None, tests_passed=None, rescan_completed=None, before_sbom_path=None,
            after_sbom_path=None, removed_findings=[], new_findings=[], remaining_findings=list(
                ctx.proposal(proposal_id).finding_ids),
            warnings=[f"validator unavailable: {type(exc).__name__}: {str(exc)[:300]}"],
            started_at=started, finished_at=utc_now())
    write_json_atomic(ctx.run_dir / "validation.json", result.to_json_dict())
    target = _STATE_FOR_VALIDATION[result.status]
    ctx.log.transition(wf, target, actor_type=ActorType.TOOL, actor_label="validator",
                       related_ids=[proposal_id], message=f"validation {result.status.value}: "
                       + ("; ".join(result.warnings)[:400] or "see validation.json"))
    _set_status(ctx, ctx.proposal(proposal_id), target)
    return result
