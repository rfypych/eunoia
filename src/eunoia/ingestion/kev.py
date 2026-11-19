"""CISA Known Exploited Vulnerabilities (KEV) catalog (CC0).

The KEV JSON feed is polled daily; the diff is on ``cveID``. Syncing
only flips the ``kev`` flag (and ``kev_date_added``) on ``cve_cache``
rows — it never overwrites NVD data. A KEV-only row (no NVD fetch yet)
carries no ``expires_at``, so a later :func:`eunoia.enrich.enrich_cve`
still fetches from NVD instead of serving an empty "fresh" row.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

import httpx

from eunoia.ingestion.nvd import default_http_client
from eunoia.models import CveCache

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/json/"
    "all-known-exploited-vulnerabilities.json"
)


def fetch_kev(client: httpx.Client | None = None) -> dict[str, date]:
    """Fetch the KEV catalog as ``{cve_id: date_added}``.

    Task 7 triage item: a malformed body (non-JSON, or a
    ``vulnerabilities`` entry that is not a dict) and a bad
    ``dateAdded`` must not crash the daily sync. Malformed entries
    are skipped; a non-JSON body or an HTTP failure raises
    ``httpx.HTTPError``/``ValueError`` to the caller, which is a real
    sync failure (visible, not a silent empty catalog).
    """
    own_client = client is None
    http = client or default_http_client()
    try:
        response = http.get(KEV_URL)
        response.raise_for_status()
        body = response.json()
    finally:
        if own_client:
            http.close()
    kev: dict[str, date] = {}
    if not isinstance(body, dict):
        raise ValueError("KEV feed body is not a JSON object")
    for item in body.get("vulnerabilities") or []:
        if not isinstance(item, dict):
            continue
        cve_id = item.get("cveID")
        added = item.get("dateAdded")
        if not cve_id or not added:
            continue
        try:
            kev[cve_id] = date.fromisoformat(added)
        except ValueError:
            # Bad dateAdded: skip this entry, never crash the sync.
            continue
    return kev


def sync_kev(session, client: httpx.Client | None = None) -> dict[str, int]:
    """Apply the KEV catalog to ``cve_cache``; return counts.

    ``{"total": N, "new": X, "updated": Y}`` — ``new`` counts KEV-only
    rows created, ``updated`` counts existing rows newly flagged.
    Idempotent: a second sync with the same catalog changes nothing.
    """
    kev = fetch_kev(client)
    new = 0
    updated = 0
    for cve_id, date_added in kev.items():
        row = session.get(CveCache, cve_id)
        if row is None:
            session.add(
                CveCache(
                    cve_id=cve_id,
                    kev=True,
                    kev_date_added=date_added,
                    fetched_at=datetime.now(timezone.utc),
                    expires_at=None,
                )
            )
            new += 1
        elif not row.kev or row.kev_date_added != date_added:
            row.kev = True
            row.kev_date_added = date_added
            updated += 1
    session.commit()
    return {"total": len(kev), "new": new, "updated": updated}
