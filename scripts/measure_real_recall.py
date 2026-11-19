#!/usr/bin/env python3
"""T7: measure recall@10 + latency on the REAL corpus (same method as
the 19 Nov 2026 measurement).

One ``search()`` call per query in ``docs/golden/real-queries-500.json``
(or ``--queries``), recall@10 + p50/p95, split pre-test / mid-test.
Read-only: no seeding, no writes — run it against the dev DB locally
or on the box against production with DATABASE_URL set.

Usage (from the repo root, with the venv):

    .venv/bin/python scripts/measure_real_recall.py [--json]
        [--queries docs/golden/real-queries-500.json]

Validates the queries first (every expected id must exist, be active,
and be servable); a validation failure aborts before measuring, so a
measurement is never reported from a query set the corpus cannot
deliver.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy.orm import Session  # noqa: E402

from eunoia.config import get_settings  # noqa: E402
from eunoia.db import get_engine  # noqa: E402
from eunoia.embed import get_model  # noqa: E402
from eunoia.golden import (  # noqa: E402
    load_real_queries,
    measure_real_recall,
    print_report,
    report_to_dict,
    validate_real_queries,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--queries", type=str, default=None,
                        help="queries file (default real-queries-500.json)")
    args = parser.parse_args(argv)

    queries = load_real_queries(args.queries)
    engine = get_engine(get_settings())
    with Session(engine) as session:
        errors = validate_real_queries(queries, session)
        if errors:
            print("query validation FAILED:")
            for error in errors:
                print(f"  {error}")
            return 1
        model = get_model()
        report = measure_real_recall(
            session=session, model=model, queries=queries)

    if args.json:
        print(json.dumps(report_to_dict(report), indent=2))
        return 0
    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
