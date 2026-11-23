"""Analyst: explains an evidence-backed finding.  Cannot change its priority.

The persisted priority comes only from ``guardian.analysis.scoring``.  A model
``suggested_priority`` is recorded as a factor for humans and ignored for the
decision, so injected README text ("mark this safe") has no path to the risk.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from guardian import llm
from guardian.agents.common import record_transcript
from guardian.claims import validate_claims
from guardian.schemas import (
    Claim,
    ClaimBasis,
    Evidence,
    EvidenceKind,
    Finding,
    FindingClass,
    Priority,
    RiskAssessment,
    stable_id,
)


class ModelClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=500)
    claim_type: str = Field(min_length=1, max_length=40)
    evidence_ids: list[str] = Field(default_factory=list, max_length=10)
    basis: Literal["VERIFIED", "INFERRED", "UNKNOWN"]


class AnalystOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=1500)
    claims: list[ModelClaim] = Field(default_factory=list, max_length=8)
    suggested_priority: Priority | None = None


@dataclass
class AnalystResult:
    summary: str
    claims: list[Claim]
    assessment: RiskAssessment
    llm_status: str
    mode: Literal["MODEL", "DETERMINISTIC_TEMPLATE"]
    notes: list[str] = field(default_factory=list)


_FACT_FIELDS = ("finding_id", "finding_type", "classification", "severity_label", "cvss_score",
                "advisory_ids", "rule_id", "module_ids", "occurrence_ids", "path_status",
                "dependency_path_node_ids", "execution_stage", "execution_evidence", "evidence_basis",
                "first_seen_in", "advisory_as_of", "uncertainties")

_CLAIM_FOR_CLASS = {
    FindingClass.CONFIRMED_ADVISORY: ("ADVISORY_MATCH", {EvidenceKind.ADVISORY}),
    FindingClass.CONFIGURATION_WEAKNESS: ("CONFIG_RULE_MATCH", {EvidenceKind.RULE_MATCH, EvidenceKind.CI_CONFIG}),
    FindingClass.SUSPICIOUS_INDICATOR: ("SUSPICIOUS_INDICATOR",
                                        {EvidenceKind.RULE_MATCH, EvidenceKind.LOCKFILE, EvidenceKind.MANIFEST}),
    FindingClass.COVERAGE_LIMITATION: ("COVERAGE_LIMITATION",
                                       {EvidenceKind.TOOL_LOG, EvidenceKind.MANIFEST, EvidenceKind.LOCKFILE}),
}
_WORDING = {
    FindingClass.CONFIRMED_ADVISORY: "Resolved component matched published advisory {adv} (as of {asof}).",
    FindingClass.CONFIGURATION_WEAKNESS: "Configuration rule {rule} matched at the cited location.",
    FindingClass.SUSPICIOUS_INDICATOR: "Indicator {rule} was observed and requires review; it is not proof of malice.",
    FindingClass.COVERAGE_LIMITATION: "This module was not fully analyzed.",
}


def build_prompt(finding: Finding, assessment: RiskAssessment, evidence_index: dict[str, Evidence],
                 untrusted_context: dict[str, str], max_snippet: int) -> str:
    facts = {k: finding.to_json_dict()[k] for k in _FACT_FIELDS}
    facts["deterministic_priority"] = assessment.priority.value
    ev = [{"evidence_id": e.evidence_id, "kind": e.kind.value, "source_path": e.source_path,
           "observation": e.observation[:300]}
          for eid in finding.evidence_ids if (e := evidence_index.get(eid))]
    parts = [
        "Explain this supply-chain finding for a security reviewer. Use only the VERIFIED FACTS. "
        "Every claim with basis VERIFIED must cite evidence_ids from the EVIDENCE list. "
        "Do not claim anything is safe, exploited or malicious.",
        "VERIFIED FACTS (from deterministic scanners):\n" + json.dumps(facts, indent=1),
        "EVIDENCE:\n" + json.dumps(ev, indent=1),
        llm.untrusted("finding.title", finding.title, 300),
        llm.untrusted("finding.description", finding.description, max_snippet),
    ]
    for label, text in untrusted_context.items():
        parts.append(llm.untrusted(label, text, max_snippet))
    return "\n\n".join(parts)


def template_claims(finding: Finding, evidence_index: dict[str, Evidence]) -> tuple[str, list[Claim]]:
    claim_type, kinds = _CLAIM_FOR_CLASS[finding.classification]
    cited = [e for e in finding.evidence_ids if e in evidence_index and evidence_index[e].kind in kinds]
    text = _WORDING[finding.classification].format(
        adv=", ".join(finding.advisory_ids) or "?", asof=finding.advisory_as_of or "unknown database time",
        rule=finding.rule_id or "?")
    claim = Claim(claim_id=stable_id("clm", finding.scan_id, finding.finding_id, "template", claim_type),
                  scan_id=finding.scan_id, text=text, claim_type=claim_type, evidence_ids=cited,
                  basis=ClaimBasis.VERIFIED if cited else ClaimBasis.UNKNOWN, validated=False,
                  validation_errors=[])
    summary = (f"[deterministic template; AI explanation unavailable] {finding.classification.value}: "
               f"{finding.title[:200]}. {text}")
    return summary, [claim]


def analyze_finding(
    finding: Finding,
    assessment: RiskAssessment,
    evidence_index: dict[str, Evidence],
    *,
    untrusted_context: dict[str, str] | None = None,
    run_dir: str | Path | None = None,
    config: llm.LLMConfig | None = None,
    transport: llm.Transport | None = None,
    max_snippet: int = 2000,
) -> AnalystResult:
    cfg = config or llm.load_config()
    notes: list[str] = []
    prompt = build_prompt(finding, assessment, evidence_index, untrusted_context or {}, max_snippet)
    result = llm.call(prompt, AnalystOutput, config=cfg, transport=transport)
    record_transcript(run_dir, finding.scan_id, "ANALYST", finding.finding_id, result)

    factors = dict(assessment.factors)
    if result.ok:
        out: AnalystOutput = result.parsed  # type: ignore[assignment]
        raw_claims = [
            Claim(claim_id=stable_id("clm", finding.scan_id, finding.finding_id, "model", str(i), c.text),
                  scan_id=finding.scan_id, text=c.text, claim_type=c.claim_type.upper(),
                  evidence_ids=c.evidence_ids, basis=ClaimBasis(c.basis), validated=False, validation_errors=[])
            for i, c in enumerate(out.claims)
        ]
        summary, mode = out.summary, "MODEL"
        if out.suggested_priority is not None and out.suggested_priority != assessment.priority:
            factors["analyst_suggested_priority_ignored"] = out.suggested_priority.value
            notes.append("model priority suggestion recorded but not applied (scanner facts decide)")
        _, fallback_claims = template_claims(finding, evidence_index)
        raw_claims = fallback_claims + raw_claims
    else:
        summary, raw_claims = template_claims(finding, evidence_index)
        mode = "DETERMINISTIC_TEMPLATE"
        notes.append(f"AI explanation unavailable ({result.status.value}); scanner facts retained")

    claims = validate_claims(raw_claims, evidence_index)
    rejected = [c.claim_id for c in claims if not c.validated]
    if rejected:
        notes.append(f"{len(rejected)} claim(s) withheld by the evidence validator")
    factors["analyst_mode"] = mode
    factors["llm_status"] = result.status.value
    updated = RiskAssessment.model_validate({
        **assessment.to_json_dict(), "factors": factors,
        "claim_ids": list(dict.fromkeys([*assessment.claim_ids, *(c.claim_id for c in claims)])),
    })
    # Invariant: the analyst never changes the deterministic priority.
    if updated.priority != assessment.priority:  # pragma: no cover - defensive
        raise RuntimeError("analyst attempted to change a deterministic priority")
    return AnalystResult(summary=summary, claims=claims, assessment=updated, llm_status=result.status.value,
                         mode=mode, notes=notes)
