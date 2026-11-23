"""Remediator: proposes ONE declarative change from the strategy catalog.

The output schema has no command, script or tool field; a proposal is data.
A human-supplied candidate takes precedence.  Without a usable model or human
candidate the result is an honest ESCALATE proposal (no change), never a guess.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from guardian import llm
from guardian.agents.common import record_transcript
from guardian.schemas import (
    SCHEMA_VERSION,
    CandidateChange,
    Finding,
    FixStrategy,
    ProjectModule,
    Proposal,
    ProposalStatus,
    stable_id,
)

EXPECTED_VALIDATION = [
    "apply declarative edit in a disposable worktree only",
    "dependency resolution with install scripts disabled, in sandbox",
    "project build",
    "project tests",
    "SBOM + advisory rescan; compare before/after findings",
]


class RemediatorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    strategy: FixStrategy
    relative_path: str = Field(min_length=1, max_length=300)
    proposed_version: str | None = Field(default=None, max_length=64)
    change_description: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=1000)


class UnsafeCandidatePath(ValueError):
    pass


def _contained(repo_dir: Path, relative_path: str) -> Path:
    """Validate a candidate path BEFORE touching the filesystem."""
    from guardian.schemas import _relpath  # same rule the contract enforces

    try:
        _relpath(relative_path)
    except ValueError as exc:
        raise UnsafeCandidatePath(f"unsafe candidate path {relative_path!r}: {exc}") from exc
    root = repo_dir.resolve()
    target = (root / relative_path).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise UnsafeCandidatePath(f"candidate path {relative_path!r} escapes the snapshot") from exc
    return target


def _sha(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def build_proposal(finding: Finding, module: ProjectModule, repo_dir: Path, *, strategy: FixStrategy,
                   relative_path: str | None, proposed_version: str | None, change_description: str,
                   rationale: str, author: str) -> Proposal:
    changes = []
    if strategy != FixStrategy.ESCALATE and relative_path:
        before = _sha(_contained(repo_dir, relative_path))
        if before is None:
            strategy, rationale = FixStrategy.ESCALATE, f"{rationale} [target file {relative_path} not found]"
        else:
            changes = [CandidateChange(relative_path=relative_path, change_description=change_description,
                                       before_hash=before, after_hash=None)]
    elif strategy != FixStrategy.ESCALATE:
        strategy = FixStrategy.ESCALATE
    pid = stable_id("prop", finding.scan_id, finding.finding_id, strategy.value, relative_path or "",
                    proposed_version or "", change_description)
    return Proposal(
        schema_version=SCHEMA_VERSION, scan_id=finding.scan_id, proposal_id=pid,
        finding_ids=[finding.finding_id], target_module_id=module.module_id, strategy=strategy,
        candidate_changes=changes, proposed_version=proposed_version if changes else None,
        rationale=f"[{author}] {rationale}", evidence_ids=list(finding.evidence_ids),
        expected_validation=EXPECTED_VALIDATION, status=ProposalStatus.PROPOSED,
        audit_result_id=None, approval_event_id=None,
    )


def propose(finding: Finding, module: ProjectModule, repo_dir: Path, *, human_candidate: dict | None = None,
            run_dir: Path | None = None, config: llm.LLMConfig | None = None,
            transport: llm.Transport | None = None) -> tuple[Proposal, str]:
    """Return (proposal, source) where source is HUMAN, MODEL or ESCALATE."""
    if human_candidate:
        return build_proposal(
            finding, module, repo_dir, strategy=FixStrategy(human_candidate["strategy"]),
            relative_path=human_candidate.get("relative_path"),
            proposed_version=human_candidate.get("proposed_version"),
            change_description=human_candidate.get("change_description") or "human-proposed declarative change",
            rationale=human_candidate.get("rationale") or "human-proposed candidate", author="HUMAN",
        ), "HUMAN"
    facts = {k: finding.to_json_dict()[k] for k in ("finding_id", "classification", "advisory_ids",
                                                     "rule_id", "severity_label", "occurrence_ids")}
    prompt = "\n\n".join([
        "Propose ONE declarative remediation using only these strategies: DIRECT_UPGRADE, PARENT_UPGRADE, "
        "OVERRIDE, CI_CONFIG, ESCALATE. relative_path must be one of the ALLOWED FILES. proposed_version must "
        "be an exact version. Never include commands. If unsure, choose ESCALATE.",
        "FINDING FACTS:\n" + json.dumps(facts, indent=1),
        "ALLOWED FILES:\n" + json.dumps(sorted({*module.manifests, *module.lockfiles, *module.ci_files})),
        "RECOMMENDATIONS (from scanner; untrusted):\n" + llm.untrusted(
            "finding.recommendations", "\n".join(finding.recommendations), 1500),
    ])
    result = llm.call(prompt, RemediatorOutput, config=config, transport=transport)
    record_transcript(run_dir, finding.scan_id, "REMEDIATOR", finding.finding_id, result)
    reason = f"model {result.status.value}"
    if result.ok:
        out: RemediatorOutput = result.parsed  # type: ignore[assignment]
        try:
            return build_proposal(finding, module, repo_dir, strategy=out.strategy,
                                  relative_path=out.relative_path, proposed_version=out.proposed_version,
                                  change_description=out.change_description, rationale=out.rationale,
                                  author="MODEL"), "MODEL"
        except UnsafeCandidatePath as exc:
            reason = f"model proposed an unsafe path ({exc})"
    return build_proposal(finding, module, repo_dir, strategy=FixStrategy.ESCALATE, relative_path=None,
                          proposed_version=None, change_description="escalate to human",
                          rationale=f"no candidate: {reason}; human candidate required",
                          author="SYSTEM"), "ESCALATE"
