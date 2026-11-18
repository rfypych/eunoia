"""Shared serving gate (Task 16, spec §6.5 takedown rule).

One definition of "servable", used by every serving surface (REST
detail / list / search, MCP tools / resources / prompt, SKILL.md): a
writeup is servable only when its status is ``active``/``updated``
(Ruling R10) AND its quality gate did not fail
(``quality_passed is False`` means a hard check failed and the record
must not go live; ``None`` means not yet gated — grandfathered as
servable, e.g. rows seeded before the gate existed).

``ensure_servable`` raises ``NotServableError`` (a distinct type, not
``ValueError`` — the Task 13 pattern), which every serving layer maps
to 410 Gone, exactly like the R10 skill gate it generalizes.
"""

from __future__ import annotations

SERVABLE_STATUSES = ("active", "updated")

__all__ = ["SERVABLE_STATUSES", "NotServableError", "ensure_servable", "is_servable"]


class NotServableError(ValueError):
    """The writeup must not be served (retracted / taken down /
    duplicate, or failed the quality gate).

    A ``ValueError`` subclass on purpose: callers written against
    the Task 12 contract (``get_skill_text`` raises ``ValueError``
    for a gated writeup) keep working, while REST/MCP catch this
    specific type first and map it to 410 Gone — distinct from
    ``SecretFoundError`` (503), so a safety refusal is never
    mislabelled as a takedown (Task 13 lesson).
    """


def is_servable(writeup) -> bool:
    """True when the writeup may be served to agents."""
    return (
        writeup.status in SERVABLE_STATUSES
        and writeup.quality_passed is not False
    )


def ensure_servable(writeup) -> None:
    """Raise ``NotServableError`` unless the writeup may be served."""
    if writeup.status not in SERVABLE_STATUSES:
        raise NotServableError(
            f"writeup {writeup.api_id} is {writeup.status}; "
            "retracted or taken-down content is not served"
        )
    if writeup.quality_passed is False:
        raise NotServableError(
            f"writeup {writeup.api_id} failed the quality gate; "
            "the record is quarantined until a human clears it"
        )
