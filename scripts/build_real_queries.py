"""Build docs/golden/real-queries-500.json from the local 500-row corpus.

Data-driven, deterministic, and verified: every expected id is checked
to exist, be active, and be servable (validate_real_queries), and every
query's expected set is computed with the SAME rules search() uses
(SQL equality for vuln_class/cwe/cve; _stack_match for tech; phrase
containment for mid-test evidence). Expected sets are kept small
(<=6 rows) so recall@10 can actually reach 1.0 — a class with 100 rows
cannot be a recall query, so those are never emitted.

"""

"""Build docs/golden/real-queries-500.json from the corpus.

Data-driven and deterministic: every expected id is checked to exist,
be active, and be servable (validate_real_queries), and every query's
expected set is computed with the SAME rules search() uses (SQL
equality for vuln_class/cwe/cve; _stack_match for tech; phrase
containment for mid-test evidence). Expected sets are kept small
(<=6 rows) so recall@10 can actually reach 1.0 — a class with 100
rows cannot be a recall query, so those are never emitted.

Expected ids are database UUIDs, so a query set built on one
database does not transfer to another: rebuild it on the database
you measure (same builder, same method).

Usage (from the repo root, with the venv):
    .venv/bin/python scripts/build_real_queries.py [--out PATH]
Writes: docs/golden/real-queries-500.json (unless --out is given).
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.golden import validate_real_queries
from eunoia.models import Writeup, WriteupVuln
from eunoia.search import StructuredQuery, _stack_match

DEFAULT_OUT = Path(__file__).resolve().parent.parent / "docs" / "golden" / "real-queries-500.json"
STOP = set("the and for with via from into that this allows allow alloweds "
           "when while which vulnerability report reports issue issues "
           "user users attacker attackers unauthenticated authenticated "
           "remote local arbitrary malicious crafted specially".split())


def api_id(w):
    return f"w_{w.id.hex}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help="where to write the query set")
    args = parser.parse_args(argv)
    engine = get_engine(get_settings())
    with Session(engine) as session:
        writeups = session.execute(
            select(Writeup).where(Writeup.status == "active")
        ).scalars().all()
        vulns = session.execute(select(WriteupVuln)).scalars().all()
    by_wid = defaultdict(list)
    for v in vulns:
        by_wid[v.writeup_id].append(v)
    servable = []
    for w in writeups:
        if w.quality_passed is False:
            continue
        v = by_wid.get(w.id, [None])[0]
        servable.append((w, v))
    print(f"servable rows: {len(servable)}")
    by_class = defaultdict(list)
    by_cwe = defaultdict(list)
    by_cve = {}
    for w, v in servable:
        if v is None:
            continue
        if v.vuln_class:
            by_class[v.vuln_class].append(w)
        if v.cwe_id:
            by_cwe[v.cwe_id].append(w)
        if v.cve_id:
            by_cve[v.cve_id] = w
    print("classes:", {k: len(v) for k, v in sorted(by_class.items())})

    queries: list[dict] = []

    def add(qid, mode, notes, **fields):
        q = {"id": qid, "mode": mode, "notes": notes}
        q.update(fields)
        queries.append(q)

    # --- pre-test: CWE queries (2..6 rows) ---
    n = 0
    for cwe in sorted(by_cwe):
        rows = by_cwe[cwe]
        if 2 <= len(rows) <= 6 and n < 4:
            n += 1
            add(f"rq{n:02d}", "pre_test",
                f"CWE {cwe}: all {len(rows)} servable rows.",
                cwe=cwe, expected_writeup_ids=[api_id(w) for w in rows])
    # --- pre-test: CVE exact lookups ---
    for cve in sorted(by_cve):
        if n >= 7:
            break
        w = by_cve[cve]
        n += 1
        add(f"rq{n:02d}", "pre_test", f"Exact CVE lookup: {w.title[:60]}.",
            cve=cve, expected_writeup_ids=[api_id(w)])
    # --- pre-test: class queries (2..6 rows) ---
    for cls in sorted(by_class):
        rows = by_class[cls]
        if 2 <= len(rows) <= 6 and n < 10:
            n += 1
            add(f"rq{n:02d}", "pre_test",
                f"Class {cls}: all {len(rows)} servable rows.",
                vuln_class=cls,
                expected_writeup_ids=[api_id(w) for w in rows])
    # --- pre-test: tech queries via _stack_match ---
    tokens = Counter()
    for w, v in servable:
        text = f"{w.title} {w.excerpt} {v.program if v else ''}".lower()
        for tok in set(re.findall(r"[a-z][a-z0-9\-]{3,}", text)):
            if tok not in STOP and "-" in tok or tok in (
                    "wordpress", "mariadb", "curl", "tomcat", "log4j"):
                tokens[tok] += 1
    tech_qs = 0
    for tok, _ in tokens.most_common():
        if tech_qs >= 4:
            break
        q = StructuredQuery(tech=(tok,), mode="pre_test")
        matched = [w for w, v in servable
                   if _stack_match(q, w, v)[0] > 0]
        if 1 <= len(matched) <= 5:
            n += 1
            tech_qs += 1
            add(f"rq{n:02d}", "pre_test",
                f"Tech {tok}: {len(matched)} servable rows match.",
                tech=[tok],
                expected_writeup_ids=[api_id(w) for w in matched])
    pre_n = n
    # --- mid-test: evidence phrases from titles ---
    mid = 0
    spaced = servable[:: max(1, len(servable) // 10)][:10]
    for w, v in spaced:
        if mid >= 10:
            break
        title_words = [t for t in re.findall(r"[A-Za-z0-9\-']+", w.title)
                       if t.lower() not in STOP and len(t) >= 3]
        phrase = None
        for size in (5, 4, 3):
            for i in range(len(title_words) - size + 1):
                cand = " ".join(title_words[i:i + size])
                hits = [x for x, _ in servable
                        if cand.lower() in f"{x.title} {x.excerpt}".lower()]
                if len(hits) == 1 and hits[0].id == w.id:
                    phrase = cand
                    break
            if phrase:
                break
        if not phrase:
            continue
        mid += 1
        n += 1
        add(f"rq{n:02d}", "mid_test",
            f"Mid-test: technique evidence for {w.title[:60]}.",
            evidence_pattern=phrase,
            expected_writeup_ids=[api_id(w)])
    print(f"built {len(queries)} queries ({pre_n} pre-test, {mid} mid-test)")
    engine2 = get_engine(get_settings())
    with Session(engine2) as session:
        errors = validate_real_queries(queries, session)
    if errors:
        print("VALIDATION FAILED:")
        for e in errors:
            print(" ", e)
        return 1
    args.out.write_text(json.dumps(queries, indent=2), encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
