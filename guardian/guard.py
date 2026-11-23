"""Deterministic Guard (project.md §8.4, C.4).  Owner: Role C.

Pure functions over structured data.  No model output, README text or package
metadata is consulted for any decision here; free text is only *scanned* for
forbidden content (shell commands), never obeyed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from guardian.analysis.scoring import is_downgrade
from guardian.schemas import (
    ActorType,
    ApprovalDecision,
    AuditVerdict,
    Event,
    Evidence,
    EvidenceKind,
    Finding,
    FindingClass,
    FixAuditResult,
    FixStrategy,
    Priority,
    ProjectModule,
    Proposal,
    WorkflowState,
    proposal_digest,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_PATH = REPO_ROOT / "config" / "policy.yaml"

# Keys the code enforces; a policy missing any of them fails closed.
_REQUIRED_POLICY = {
    ("policy_version",),
    ("scanning", "execute_repository_scripts"),
    ("agent", "may_change_scan_facts"),
    ("agent", "may_reduce_risk_without_new_evidence"),
    ("agent", "raw_untrusted_text_can_authorize_tools"),
    ("remediation", "require_explicit_human_approval"),
    ("remediation", "allow_merge_or_publish"),
    ("remediation", "fail_closed_on_missing_candidate_audit"),
    ("local_intake", "allowed_roots"),
}
# Values that must hold; anything else is a configuration Guardian refuses to run.
_REQUIRED_VALUES = {
    ("scanning", "execute_repository_scripts"): False,
    ("agent", "may_change_scan_facts"): False,
    ("agent", "raw_untrusted_text_can_authorize_tools"): False,
    ("remediation", "require_explicit_human_approval"): True,
    ("remediation", "allow_merge_or_publish"): False,
    ("remediation", "fail_closed_on_missing_candidate_audit"): True,
}


class PolicyError(RuntimeError):
    pass


class LocalPathRejected(RuntimeError):
    pass


def _get(policy: dict, path: tuple[str, ...]) -> Any:
    node: Any = policy
    for key in path:
        if not isinstance(node, dict) or key not in node:
            raise KeyError(".".join(path))
        node = node[key]
    return node


def load_policy(path: str | Path | None = None) -> dict:
    target = Path(path) if path else DEFAULT_POLICY_PATH
    try:
        policy = yaml.safe_load(target.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise PolicyError(f"policy unreadable: {type(exc).__name__}") from exc
    if not isinstance(policy, dict):
        raise PolicyError("policy must be a mapping")
    for key in _REQUIRED_POLICY:
        try:
            _get(policy, key)
        except KeyError as exc:
            raise PolicyError(f"policy missing required key {exc.args[0]} (fail closed)") from exc
    for key, expected in _REQUIRED_VALUES.items():
        if _get(policy, key) is not expected:
            raise PolicyError(f"policy {'.'.join(key)} must be {expected}; Guardian refuses to run otherwise")
    return policy


def check_local_path(path: str | Path, policy: dict, repo_root: Path = REPO_ROOT) -> Path:
    """``scan --local`` accepts only team-owned fixture roots from policy."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = (Path.cwd() / candidate)
    resolved = candidate.resolve()
    if not resolved.is_dir():
        raise LocalPathRejected("local path is not a directory")
    for root in _get(policy, ("local_intake", "allowed_roots")):
        allowed = (repo_root / root).resolve()
        try:
            resolved.relative_to(allowed)
            return resolved
        except ValueError:
            continue
    raise LocalPathRejected("local path is outside policy local_intake.allowed_roots")


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass
class GuardCheck:
    name: str
    passed: bool
    detail: str = ""
    outcome_if_failed: WorkflowState = WorkflowState.BLOCKED


@dataclass
class GuardDecision:
    checks: list[GuardCheck] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> list[GuardCheck]:
        return [c for c in self.checks if not c.passed]

    @property
    def next_state(self) -> WorkflowState:
        failed = self.failures
        if not failed:
            return WorkflowState.REVIEW_PENDING
        if any(c.outcome_if_failed == WorkflowState.REJECTED for c in failed):
            return WorkflowState.REJECTED
        return WorkflowState.BLOCKED

    def summary(self) -> str:
        if self.allowed:
            return "all guard checks passed"
        return "; ".join(f"{c.name}: {c.detail}" for c in self.failures)

    def add(self, name: str, passed: bool, detail: str = "",
            outcome: WorkflowState = WorkflowState.BLOCKED) -> None:
        self.checks.append(GuardCheck(name, bool(passed), detail if not passed else "", outcome))


EXACT_VERSION = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$")
_SHELL = re.compile(
    r"\$\(|`|&&|\|\||;\s*\S|\|\s*\w|>\s*/|\brm\s+-|\bcurl\b|\bwget\b|\bbash\b|\bsh\s+-c\b|\bpowershell\b"
    r"|\bpwsh\b|\bcmd(\.exe)?\s*/c\b|\bnpx\b|\bnpm\s+(install|i|exec|run)\b|\bpip\s+install\b|\beval\b"
    r"|\bchmod\b|\bsudo\b|\bnc\s+-",
    re.IGNORECASE,
)
_UPGRADE_STRATEGIES = {FixStrategy.DIRECT_UPGRADE, FixStrategy.PARENT_UPGRADE, FixStrategy.OVERRIDE}


def contains_shell(text: str) -> bool:
    return bool(_SHELL.search(text or ""))


def _file_sha256(path: Path) -> str | None:
    import hashlib

    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_proposal(
    proposal: Proposal,
    *,
    findings: dict[str, Finding],
    evidence_index: dict[str, Evidence],
    modules: dict[str, ProjectModule],
    repo_dir: Path,
    audit: FixAuditResult | None,
    critic_verdict: str | None,
    policy: dict,
) -> GuardDecision:
    d = GuardDecision()
    R = WorkflowState.REJECTED
    allowed_strategies = set(policy.get("remediation", {}).get("allowed_strategies", []))
    d.add("strategy_allowed", proposal.strategy.value in allowed_strategies,
          f"strategy {proposal.strategy.value} not in policy", R)
    d.add("strategy_not_escalate", proposal.strategy != FixStrategy.ESCALATE,
          "ESCALATE proposals carry no change; route to a human without validation")

    missing_f = [f for f in proposal.finding_ids if f not in findings]
    d.add("findings_exist", not missing_f, f"unknown findings {missing_f}", R)
    weak = [f.finding_id for fid in proposal.finding_ids if (f := findings.get(fid))
            and (not f.evidence_ids or any(e not in evidence_index for e in f.evidence_ids)
                 or f.classification == FindingClass.COVERAGE_LIMITATION)]
    d.add("findings_evidence_backed", not weak, f"findings lack ledger evidence {weak}", R)

    missing_e = [e for e in proposal.evidence_ids if e not in evidence_index]
    model_only = proposal.evidence_ids and all(
        evidence_index[e].kind == EvidenceKind.MODEL_OUTPUT for e in proposal.evidence_ids if e in evidence_index)
    d.add("proposal_evidence_exists", not missing_e and bool(proposal.evidence_ids),
          f"missing/empty evidence {missing_e}", R)
    d.add("proposal_evidence_not_model_only", not model_only, "model output is not evidence", R)

    module = modules.get(proposal.target_module_id)
    d.add("target_module_exists", module is not None, f"unknown module {proposal.target_module_id}", R)

    if proposal.strategy in _UPGRADE_STRATEGIES:
        v = proposal.proposed_version or ""
        d.add("proposed_version_exact", bool(EXACT_VERSION.fullmatch(v)),
              f"proposed_version {v!r} is not an exact registry version (no ranges/URLs/git/tags)", R)

    for change in proposal.candidate_changes:
        p = change.relative_path
        d.add(f"no_shell:{p}", not contains_shell(change.change_description),
              "change_description contains shell/command content; only declarative edits are allowed", R)
        if module is not None:
            mod_root = PurePosixPath(module.relative_path)
            in_module = module.relative_path == "." or PurePosixPath(p).is_relative_to(mod_root)
            permitted = set(module.manifests) | set(module.lockfiles)
            if proposal.strategy == FixStrategy.CI_CONFIG:
                permitted = set(module.ci_files)
            d.add(f"path_permitted:{p}", in_module and p in permitted,
                  f"{p} is not a manifest/lockfile{'/CI file' if proposal.strategy == FixStrategy.CI_CONFIG else ''} "
                  "of the target module", R)
        current = _file_sha256(repo_dir / p)
        d.add(f"before_hash:{p}", current is not None and current == change.before_hash,
              "file missing or changed since proposal (stale before_hash)")

    fail_closed = policy["remediation"]["fail_closed_on_missing_candidate_audit"]
    if audit is None:
        d.add("candidate_audit_present", not fail_closed, "candidate audit unavailable (fail closed)")
    else:
        d.add("audit_matches_proposal", audit.proposal_id == proposal.proposal_id
              and audit.audit_result_id == proposal.audit_result_id, "audit result is for another proposal")
        d.add("audit_verdict", audit.verdict == AuditVerdict.ALLOW_REVIEW,
              f"audit verdict {audit.verdict.value}: fix not approvable",
              R if audit.verdict == AuditVerdict.REJECT else WorkflowState.BLOCKED)

    if critic_verdict == "VETO":
        d.add("critic", False, "Critic vetoed the proposal", R)
    elif critic_verdict == "ESCALATE":
        d.notes.append("Critic escalated: reviewer must read critic concerns")
    elif critic_verdict is None:
        d.notes.append("Critic not run (optional); deterministic checks still enforced")
    return d


def check_risk_change(before: Priority, after: Priority, new_evidence_ids: list[str],
                      evidence_index: dict[str, Evidence], policy: dict) -> GuardCheck:
    """A downgrade needs genuinely new, non-model evidence (§8.2)."""
    if not is_downgrade(before, after):
        return GuardCheck("risk_change", True)
    if policy["agent"].get("may_reduce_risk_without_new_evidence", False):
        return GuardCheck("risk_change", True)  # pragma: no cover - forbidden by load_policy defaults
    real = [e for e in new_evidence_ids
            if e in evidence_index and evidence_index[e].kind != EvidenceKind.MODEL_OUTPUT]
    if real:
        return GuardCheck("risk_change", True)
    return GuardCheck("risk_change", False,
                      f"downgrade {Priority(before).value}->{Priority(after).value} without new non-model evidence")


def _parse_ts(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def check_approval(
    approval_event_id: str | None,
    *,
    proposal: Proposal,
    audit: FixAuditResult | None,
    events: list[Event],
    policy: dict,
    workflow_state: WorkflowState | None,
    now: datetime | None = None,
) -> GuardDecision:
    """Is there a fresh, human, proposal-hash-bound approval permitting VALIDATING?"""
    d = GuardDecision()
    now = now or datetime.now(timezone.utc)
    by_id = {e.event_id: e for e in events}
    event = by_id.get(approval_event_id or "")
    d.add("approval_event_exists", event is not None, "no approval event (validation requires fresh approval)")
    if event is None:
        return d
    rec = event.approval
    d.add("approval_by_human", event.actor_type == ActorType.HUMAN and rec is not None,
          "event is not a human approval record")
    if rec is None:
        return d
    d.add("decision_is_approve", rec.decision == ApprovalDecision.APPROVE, f"decision is {rec.decision.value}")
    d.add("same_scan", rec.scan_id == proposal.scan_id == event.scan_id, "approval belongs to another scan")
    d.add("same_proposal", rec.proposal_id == proposal.proposal_id, "approval is for another proposal")
    d.add("proposal_hash_current", rec.proposal_sha256 == proposal_digest(proposal),
          "stale approval: proposal content changed after approval")
    d.add("policy_version_current", rec.policy_version == policy["policy_version"],
          "approval was made under a different policy version")
    d.add("audit_allows_review", audit is not None and audit.verdict == AuditVerdict.ALLOW_REVIEW
          and rec.audit_result_id == audit.audit_result_id == proposal.audit_result_id,
          "approval not bound to an ALLOW_REVIEW audit of this proposal")
    ttl = int(policy.get("remediation", {}).get("approval_ttl_minutes", 120))
    expired = _parse_ts(rec.decided_at) + timedelta(minutes=ttl) < now or (
        rec.expires_at is not None and _parse_ts(rec.expires_at) < now)
    d.add("approval_not_expired", not expired, "approval expired")
    later = [e for e in events if e.approval is not None and e.approval.proposal_id == proposal.proposal_id
             and e.timestamp >= event.timestamp and e.event_id != event.event_id]
    revoked = [e for e in later if e.approval.decision in (ApprovalDecision.REVOKE, ApprovalDecision.REJECT)]
    d.add("approval_not_revoked", not revoked, "approval was revoked or superseded by a rejection")
    d.add("workflow_state_approved", workflow_state == WorkflowState.APPROVED,
          f"remediation workflow is {workflow_state.value if workflow_state else None}, not APPROVED")
    return d
