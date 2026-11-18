"""Credential/token regex scan (spec §6.4, §6.5 quality gate (d)).

``scan_secrets`` flags common live-secret patterns in excerpts, skill
text, and any other registry content before it goes live. A finding
never contains the secret itself: the preview shows surrounding context
with the match replaced by ``[REDACTED <pattern>]``.

This is a pattern scan, not a verdict on liveness: a match means "hold
for human review", never "this credential is live". False positives are
possible by design; the gate fails closed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Specific patterns first: when two patterns overlap the same span, the
# first (most specific) finding wins and the overlapping one is dropped.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token",
     re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("private_key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("stripe_live_key", re.compile(r"sk_live_[A-Za-z0-9]{16,}")),
    ("bearer_token",
     re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-]{20,}")),
    ("generic_credential_assignment", re.compile(
        r"(?i)(?:api[_-]?key|access[_-]?token|secret|password|passwd|pwd)"
        r"\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}['\"]?")),
]

_CONTEXT = 20


@dataclass(frozen=True)
class Finding:
    """One secret-pattern match. ``preview`` never holds the secret."""

    pattern: str
    start: int
    end: int
    preview: str


def _preview(text: str, start: int, end: int, pattern: str) -> str:
    before = text[max(0, start - _CONTEXT):start]
    after = text[end:end + _CONTEXT]
    return f"{before}[REDACTED {pattern}]{after}"


def scan_secrets(text: str | None) -> list[Finding]:
    """All secret-pattern findings in ``text`` (empty list when clean)."""
    if not text:
        return []
    findings: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for name, pattern in _PATTERNS:
        for match in pattern.finditer(text):
            start, end = match.span()
            if any(start < t_end and end > t_start for t_start, t_end in taken):
                continue
            taken.append((start, end))
            findings.append(Finding(
                pattern=name, start=start, end=end,
                preview=_preview(text, start, end, name)))
    findings.sort(key=lambda f: f.start)
    return findings


def contains_secret(text: str | None) -> bool:
    """True if ``scan_secrets`` finds anything."""
    return bool(scan_secrets(text))
