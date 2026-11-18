"""Scope Gate (spec §6.2, §5.8 step 0): allowlist + denylist, default-deny.

The gate runs outside the planner, on every execution tool call, and
checks the redirect target too — a redirect to a host outside scope is
blocked, never followed blindly. Discovery must never widen the mandate
on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse


class ScopeBlocked(Exception):
    """Raised by :meth:`ScopeGate.require` for an out-of-scope target."""


@dataclass(frozen=True)
class Scope:
    """Written engagement scope: exact allowlist + denylist.

    Entries are hostnames (``lab.example.internal``); a subdomain of an
    allowlisted host is in scope, but a mere suffix match is not
    (``notexample.internal`` does not match ``example.internal``).
    """

    allowlist: tuple[str, ...] = ()
    denylist: tuple[str, ...] = ()
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowlist",
                           tuple(_normalize_entry(h) for h in self.allowlist))
        object.__setattr__(self, "denylist",
                           tuple(_normalize_entry(h) for h in self.denylist))


def _normalize_entry(entry: str) -> str:
    entry = entry.strip().lower()
    if entry.startswith("*."):
        entry = entry[2:]
    if ":" in entry:  # strip any port from a host entry
        entry = entry.rsplit(":", 1)[0]
    return entry


def _extract_host(host_or_url: str) -> str | None:
    """Host part of a bare host, host:port, or URL; None if unparseable."""
    if not host_or_url or not host_or_url.strip():
        return None
    value = host_or_url.strip()
    try:
        parsed = urlparse(value if "://" in value else f"//{value}")
    except ValueError:
        return None
    host = (parsed.hostname or "").lower()
    return host or None


def _host_matches(host: str, pattern: str) -> bool:
    return host == pattern or host.endswith("." + pattern)


class ScopeGate:
    """Deterministic scope check; no model involved."""

    @staticmethod
    def check(host_or_url: str, scope: Scope) -> bool:
        """True only if the host is allowlisted and not denylisted.

        Default-deny: an empty allowlist allows nothing.
        """
        host = _extract_host(host_or_url)
        if host is None:
            return False
        if any(_host_matches(host, d) for d in scope.denylist):
            return False
        if not scope.allowlist:
            return False
        return any(_host_matches(host, a) for a in scope.allowlist)

    @staticmethod
    def check_redirect(source_url: str, redirect_url: str, scope: Scope) -> bool:
        """A redirect is allowed only if its target passes the gate.

        The source URL is irrelevant to the decision: only the target
        host matters, and it is checked, never followed blindly.
        """
        return ScopeGate.check(redirect_url, scope)

    @staticmethod
    def require(host_or_url: str, scope: Scope) -> bool:
        """Like :meth:`check`, but raises :class:`ScopeBlocked` on denial."""
        if not ScopeGate.check(host_or_url, scope):
            raise ScopeBlocked(
                f"target {host_or_url!r} is outside scope "
                f"{scope.name or scope.allowlist!r}"
            )
        return True
