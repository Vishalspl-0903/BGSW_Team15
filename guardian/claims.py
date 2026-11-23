"""Deterministic evidence claim validator (project.md §8.2).

A ``VERIFIED`` claim survives only if every cited evidence ID exists, belongs
to the same scan, is not model output, and its evidence kind is permitted for
the claim type.  Safety/exploitation assertions are never verifiable here.
Rejected claims are kept (``validated=False`` + reasons) so the audit trail
shows what was withheld; underlying findings are never deleted.
"""

from __future__ import annotations

import re

from guardian.schemas import Claim, ClaimBasis, Evidence, EvidenceKind

K = EvidenceKind

#: claim_type -> evidence kinds that can support it as VERIFIED.
CLAIM_EVIDENCE_POLICY: dict[str, frozenset[EvidenceKind]] = {
    "PACKAGE_PRESENT": frozenset({K.LOCKFILE, K.SBOM, K.MANIFEST}),
    "DECLARED_DEPENDENCY": frozenset({K.MANIFEST, K.LOCKFILE}),
    "DEPENDENCY_PATH": frozenset({K.LOCKFILE, K.SBOM}),
    "ADVISORY_MATCH": frozenset({K.ADVISORY}),
    "CONFIG_RULE_MATCH": frozenset({K.RULE_MATCH, K.CI_CONFIG}),
    "SUSPICIOUS_INDICATOR": frozenset({K.RULE_MATCH, K.LOCKFILE, K.MANIFEST}),
    "COVERAGE_LIMITATION": frozenset({K.TOOL_LOG, K.MANIFEST, K.LOCKFILE}),
    "TOOL_STATUS": frozenset({K.TOOL_LOG}),
    "BUILD_RESULT": frozenset({K.VALIDATION}),
    "TEST_RESULT": frozenset({K.VALIDATION}),
    "RESCAN_RESULT": frozenset({K.VALIDATION, K.ADVISORY, K.SBOM}),
}

#: Claim types that can never be VERIFIED by this system.
NEVER_VERIFIABLE = frozenset({
    "FIX_SAFETY", "PACKAGE_SAFE", "NOT_VULNERABLE", "EXPLOITATION", "UNREACHABLE",
    "RISK_REDUCTION", "MALICIOUS",
})

# Absolute safety/compromise wording a model must not assert, at any basis.
_FORBIDDEN_WORDING = re.compile(
    r"\b(is|are|now|completely|fully|totally)\s+(safe|secure|harmless|benign)\b"
    r"|\bno\s+(security\s+)?risk\b|\bnot\s+vulnerable\b|\b(has\s+been|was|is)\s+exploited\b"
    r"|\bis\s+malicious\b|\bunreachable\b|\bguarantee[sd]?\b|\bmark\s+(this|it|as)\s+safe\b"
    r"|\bfalse\s+positive\b",
    re.IGNORECASE,
)


def claim_errors(claim: Claim, evidence_index: dict[str, Evidence]) -> list[str]:
    errors: list[str] = []
    if _FORBIDDEN_WORDING.search(claim.text):
        errors.append("claim asserts safety/exploitation/false-positive wording that evidence cannot support")
    missing = [e for e in claim.evidence_ids if e not in evidence_index]
    if missing:
        errors.append(f"cites unknown evidence {missing}")
    cited = [evidence_index[e] for e in claim.evidence_ids if e in evidence_index]
    foreign = [e.evidence_id for e in cited if e.scan_id != claim.scan_id]
    if foreign:
        errors.append(f"cites evidence from another scan {foreign}")
    if claim.basis == ClaimBasis.VERIFIED:
        if not claim.evidence_ids:
            errors.append("VERIFIED claim cites no evidence")
        if claim.claim_type in NEVER_VERIFIABLE:
            errors.append(f"claim_type {claim.claim_type} cannot be VERIFIED")
        allowed = CLAIM_EVIDENCE_POLICY.get(claim.claim_type)
        if allowed is None and claim.claim_type not in NEVER_VERIFIABLE:
            errors.append(f"claim_type {claim.claim_type} has no verification policy")
        model_backed = [e.evidence_id for e in cited if e.kind == K.MODEL_OUTPUT]
        if model_backed:
            errors.append(f"model output is not supporting evidence {model_backed}")
        if allowed is not None:
            support = [e for e in cited if e.kind in allowed and e.scan_id == claim.scan_id]
            if not support:
                kinds = sorted({e.kind.value for e in cited})
                errors.append(f"no same-scan evidence of a kind that supports {claim.claim_type} "
                              f"(cited kinds {kinds})")
    return errors


def validate_claims(claims: list[Claim], evidence_index: dict[str, Evidence]) -> list[Claim]:
    """Return copies with ``validated``/``validation_errors`` set deterministically."""
    out = []
    for claim in claims:
        errors = claim_errors(claim, evidence_index)
        out.append(Claim.model_validate({**claim.to_json_dict(), "validated": not errors,
                                         "validation_errors": errors}))
    return out
