"""Deterministic initial priority (project.md §8.3, §18.5).  Owner: Role C.

Transparent rules, no weights, no model.  Inputs are only *structured* finding
facts (classification, published severity, CVSS, stage evidence, evidence
existence, graph resolution).  Free text — title, description, recommendations,
package README/metadata — is never read here, so injected instructions cannot
change a priority.

Rules (first match decides the rule result):

  R0  cited evidence missing from the ledger, or factual finding without
      evidence                                     -> NEEDS_REVIEW
  R1  COVERAGE_LIMITATION                          -> UNASSESSED
  R2  CONFIRMED_ADVISORY on an occurrence the graph does not mark RESOLVED
                                                   -> NEEDS_REVIEW (contradiction)
  R3  CONFIRMED_ADVISORY, CRITICAL/HIGH + CONFIRMED INSTALL/BUILD/CI exposure
                                                   -> P0
  R4  CONFIRMED_ADVISORY by published severity: CRITICAL/HIGH -> P1,
      MEDIUM/MODERATE -> P2, LOW -> P3, unknown -> NEEDS_REVIEW
      (CVSS is used only when no label is published: >=7 P1, >=4 P2, else P3)
  R5  SUSPICIOUS_INDICATOR / CONFIGURATION_WEAKNESS -> NEEDS_REVIEW
                                                     (P1 if CONFIRMED CI/INSTALL exposure)

Monotonicity: the final priority is never less urgent than the producer's
initial ``finding.priority`` (see ``more_urgent``).  Unknown reachability and
KEV status are listed in ``unknowns`` and never scored as zero.
"""

from __future__ import annotations

from guardian.claims import validate_claims as _validate_claims
from guardian.schemas import (
    SCHEMA_VERSION,
    Claim,
    Evidence,
    ExecutionEvidence,
    ExecutionStage,
    Finding,
    FindingClass,
    GraphBundle,
    Priority,
    Resolution,
    RiskAssessment,
)

P = Priority
_NUMERIC = {P.P0: 0, P.P1: 1, P.P2: 2, P.P3: 3}
_SEVERITY = {"CRITICAL": P.P1, "HIGH": P.P1, "MEDIUM": P.P2, "MODERATE": P.P2, "LOW": P.P3}
_EXPOSED_STAGES = {ExecutionStage.INSTALL, ExecutionStage.BUILD, ExecutionStage.CI}


def more_urgent(a: Priority, b: Priority) -> Priority:
    """The more urgent of two priorities.

    Numeric vs numeric: lower number wins.  P0/P1 always beat a categorical
    value (a human-review label must not hide known urgency).  Otherwise a
    categorical NEEDS_REVIEW/UNASSESSED beats P2/P3, because unknown must not be
    presented as low risk.  NEEDS_REVIEW beats UNASSESSED.
    """
    a, b = Priority(a), Priority(b)
    if a in _NUMERIC and b in _NUMERIC:
        return a if _NUMERIC[a] <= _NUMERIC[b] else b
    for top in (P.P0, P.P1):
        if top in (a, b):
            return top
    for cat in (P.NEEDS_REVIEW, P.UNASSESSED):
        if cat in (a, b):
            return cat
    return a  # pragma: no cover - exhaustive above


def is_downgrade(before: Priority, after: Priority) -> bool:
    """True if ``after`` would present the finding as less urgent than ``before``."""
    return Priority(before) != Priority(after) and more_urgent(before, after) == Priority(before)


def _severity_priority(finding: Finding) -> tuple[Priority, str | None]:
    label = (finding.severity_label or "").strip().upper()
    if label in _SEVERITY:
        return _SEVERITY[label], label
    if not label and finding.cvss_score is not None:
        score = finding.cvss_score
        derived = "HIGH" if score >= 7.0 else "MEDIUM" if score >= 4.0 else "LOW"
        return _SEVERITY[derived], f"cvss:{score}"
    return P.NEEDS_REVIEW, None


def _assess(finding: Finding, graph: GraphBundle | None, evidence_index: dict[str, Evidence]) -> RiskAssessment:
    factors: dict = {
        "classification": finding.classification.value,
        "finding_type": finding.finding_type.value,
        "severity_label": finding.severity_label,
        "cvss_score": finding.cvss_score,
        "execution_stage": finding.execution_stage.value,
        "execution_evidence": finding.execution_evidence.value,
        "path_status": finding.path_status.value,
        "evidence_basis": finding.evidence_basis.value,
        "producer_priority": finding.priority.value,
        "kev_status": None,
        "reachability": None,
    }
    unknowns = list(dict.fromkeys([
        *finding.uncertainties,
        "kev_status not evaluated",
        "reachability not demonstrated (not scored as zero)",
    ]))
    missing = [e for e in finding.evidence_ids if e not in evidence_index]
    factors["evidence_missing"] = missing
    exposed = finding.execution_stage in _EXPOSED_STAGES and \
        finding.execution_evidence == ExecutionEvidence.CONFIRMED

    cls = finding.classification
    if missing or (not finding.evidence_ids and cls != FindingClass.COVERAGE_LIMITATION):
        rule, result = "R0", P.NEEDS_REVIEW
        rationale = f"cited evidence missing from ledger {missing}; verified priority withheld"
    elif cls == FindingClass.COVERAGE_LIMITATION:
        rule, result = "R1", P.UNASSESSED
        rationale = "coverage limitation: not fully analyzed, so risk is unassessed (not low)"
    elif cls == FindingClass.CONFIRMED_ADVISORY:
        unresolved = []
        if graph is not None:
            comps = {c.occurrence_id: c for c in graph.components}
            unresolved = [o for o in finding.occurrence_ids
                          if o not in comps or comps[o].resolution != Resolution.RESOLVED]
        factors["unresolved_occurrences"] = unresolved
        sev, basis = _severity_priority(finding)
        factors["severity_basis"] = basis
        if unresolved:
            rule, result = "R2", P.NEEDS_REVIEW
            rationale = f"advisory match on occurrences not resolved in graph {unresolved}"
        elif sev == P.P1 and exposed:
            rule, result = "R3", P.P0
            rationale = (f"{basis} published severity with CONFIRMED {finding.execution_stage.value} "
                         "exposure")
        elif sev == P.NEEDS_REVIEW:
            rule, result = "R4", P.NEEDS_REVIEW
            rationale = "advisory matched but no published severity; needs human review"
        else:
            rule, result = "R4", sev
            rationale = f"published severity {basis} on resolved package; reachability unknown"
    else:
        rule = "R5"
        result = P.P1 if exposed else P.NEEDS_REVIEW
        rationale = (f"{cls.value} indicator requires review"
                     + (f"; CONFIRMED {finding.execution_stage.value} exposure" if exposed else ""))

    final = more_urgent(result, finding.priority)
    factors["rule"] = rule
    factors["rule_priority"] = result.value
    if final != result:
        rationale += f"; kept producer priority {finding.priority.value} (never downgraded)"
    return RiskAssessment(
        schema_version=SCHEMA_VERSION, scan_id=finding.scan_id, finding_id=finding.finding_id,
        priority=final, factors=factors, rationale=rationale,
        evidence_ids=[e for e in finding.evidence_ids if e in evidence_index],
        unknowns=unknowns, claim_ids=[],
    )


def score_findings(findings: list[Finding], graph: GraphBundle | None,
                   evidence_index: dict[str, Evidence]) -> list[RiskAssessment]:
    """§9.4 public signature.  Pure, deterministic, order-preserving."""
    return [_assess(f, graph, evidence_index) for f in findings]


def validate_claims(claims: list[Claim], evidence_index: dict[str, Evidence]) -> list[Claim]:
    """§9.4 public signature; implementation lives in ``guardian.claims``."""
    return _validate_claims(claims, evidence_index)
