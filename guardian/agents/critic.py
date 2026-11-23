"""Critic: may VETO or ESCALATE a proposal.  It can never authorize one.

Any model failure (invalid JSON, refusal, timeout, schema mismatch) becomes
ESCALATE — bad model output triggers escalation, not success.  With the model
disabled the Critic is simply not run and the deterministic Guard still decides.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian import llm
from guardian.agents.common import record_transcript
from guardian.schemas import Finding, FixAuditResult, Proposal


class CriticOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["NO_OBJECTION", "ESCALATE", "VETO"]
    concerns: list[str] = Field(default_factory=list, max_length=8)


@dataclass
class CriticResult:
    verdict: Literal["NO_OBJECTION", "ESCALATE", "VETO"] | None
    concerns: list[str]
    llm_status: str


def review(proposal: Proposal, findings: list[Finding], audit: FixAuditResult | None, *,
           run_dir: Path | None = None, config: llm.LLMConfig | None = None,
           transport: llm.Transport | None = None) -> CriticResult:
    cfg = config or llm.load_config()
    if not cfg.enabled:
        return CriticResult(None, [], llm.LLMStatus.DISABLED.value)
    summary = {
        "proposal": {k: proposal.to_json_dict()[k] for k in
                     ("proposal_id", "strategy", "proposed_version", "candidate_changes", "evidence_ids")},
        "findings": [{k: f.to_json_dict()[k] for k in ("finding_id", "classification", "advisory_ids",
                                                        "severity_label", "uncertainties")} for f in findings],
        "audit": audit.to_json_dict() if audit else None,
    }
    prompt = ("Critique this remediation proposal. Check unsupported claims, incorrect fix versions, new risk "
              "and missing evidence. You may only return NO_OBJECTION, ESCALATE or VETO; you cannot approve.\n\n"
              + json.dumps(summary, indent=1) + "\n\n"
              + llm.untrusted("proposal.rationale", proposal.rationale, 1000))
    result = llm.call(prompt, CriticOutput, config=cfg, transport=transport)
    record_transcript(run_dir, proposal.scan_id, "CRITIC", proposal.proposal_id, result)
    if result.ok:
        out: CriticOutput = result.parsed  # type: ignore[assignment]
        return CriticResult(out.verdict, [c[:300] for c in out.concerns], result.status.value)
    return CriticResult("ESCALATE", [f"critic unavailable or invalid output ({result.status.value})"],
                        result.status.value)
