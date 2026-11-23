"""Approval-bound validation entry point reserved for the Day 2 workflow."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from guardian.schemas import ValidationResult


class ValidationBlocked(RuntimeError):
    """Validation cannot safely proceed with missing canonical interfaces."""


def validate_approved_proposal(
    scan_id: str, proposal_id: str, approved_event_id: str, run_dir: str
) -> "ValidationResult":
    """Fail closed until C's approval API and schemas are available.

    Role A must not invent approval semantics.  This explicit blocker prevents
    mutation or command execution before the proposal-hash-bound approval
    contract is merged and can be verified.
    """
    del scan_id, proposal_id, approved_event_id, run_dir
    raise ValidationBlocked(
        "validation is BLOCKED until C's proposal-hash-bound approval interface is merged"
    )
