"""Redaction and bounding of text before it reaches logs, prompts or reports.

Best-effort, pattern-based (§5.3, C.3): this reduces accidental disclosure; it
is not a guarantee that no secret can ever pass.  Callers must still avoid
sending secrets in the first place.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
     "[REDACTED:private-key]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), "[REDACTED:github-token]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED:github-token]"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "[REDACTED:api-key]"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"), "[REDACTED:api-key]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), "[REDACTED:slack-token]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED:aws-key]"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{30,}\b"), "[REDACTED:npm-token]"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), "[REDACTED:jwt]"),
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token))\s+[^\s\"']+"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)\b([A-Z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|auth)[A-Z0-9_]*)"
                r"(\s*[:=]\s*)([\"']?)[^\s\"',;]{4,}\3"), r"\1\2\3[REDACTED]\3"),
    (re.compile(r"(?i)(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED:email]"),
    (re.compile(r"(?i)\b[A-Z]:\\(?:[^\\\s\"'<>|]+\\)*[^\\\s\"'<>|]*"), "[HOST-PATH]"),
    (re.compile(r"(?<![\w.])/(?:home|Users|root|var|tmp|etc|opt|mnt|private)/[^\s\"'<>]*"), "[HOST-PATH]"),
]


def redact(text: str) -> str:
    """Replace credential-like, email and absolute host-path content."""
    if not text:
        return text
    out = text
    for pattern, repl in _PATTERNS:
        out = pattern.sub(repl, out)
    return out


def bound(text: str, max_chars: int) -> str:
    """Truncate to ``max_chars`` with an explicit marker (never silently)."""
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    marker = f"…[TRUNCATED {len(text) - max_chars} chars]"
    keep = max(0, max_chars - len(marker))
    return text[:keep] + marker


def redact_bounded(text: str, max_chars: int) -> str:
    return bound(redact(text or ""), max_chars)
