#!/usr/bin/env python3
"""Task 15: measure golden-set recall@10 + latency (spec §8).

Seeds the golden corpus into the dev DB if missing (idempotent),
embeds with the real model, runs the 50 golden queries through
``eunoia.search.search`` and prints the measured report as-is —
recall@10 and latencies are reported, never claimed. Then runs the
reference harness once per stack (spring-boot / tomcat / log4j) and
reports end-to-end run latency and queries per run (§9 Q8).

Usage (from the repo root):

    python scripts/measure_recall.py [--skip-seed] [--json] [--harness-runs N]

Re-measure on every embedding/ranking change before shipping it.
No live network calls: everything runs against the local DB.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sqlalchemy.orm import Session  # noqa: E402

from eunoia.config import get_settings  # noqa: E402
from eunoia.db import get_engine  # noqa: E402
from eunoia.embed import get_model  # noqa: E402
from eunoia.golden import (  # noqa: E402
    measure_recall,
    print_report,
    report_to_dict,
    seed_golden_corpus,
)
from eunoia.harness.loop import run_loop  # noqa: E402
from eunoia.harness.state import Fingerprint  # noqa: E402
from eunoia.safety.scope import Scope  # noqa: E402

HARNESS_STACKS = [
    ("spring-boot", "3.2.0"),
    ("tomcat", "9.0.31"),
    ("log4j", "2.14.1"),
]


def _harness_probe(session: Session, model, runs: int) -> list[dict]:
    """Run the reference harness once per stack; time each run and
    count its registry lookups (queries per run, §9 Q8)."""
    out: list[dict] = []
    scope = Scope(allowlist=["app.lab.internal"])
    for tech, version in HARNESS_STACKS:
        for _ in range(runs):
            t0 = time.perf_counter()
            report = run_loop(
                scope=scope,
                lab_target="https://app.lab.internal",
                session=session, model=model,
                fingerprinter=lambda target, t=tech, v=version: [
                    Fingerprint(technology=t, version=v, confidence=0.9,
                                bukti=("golden measurement",)),
                ],
            )
            wall_ms = (time.perf_counter() - t0) * 1000.0
            out.append({
                "stack": f"{tech} {version}",
                "wall_ms": round(wall_ms, 2),
                "queries_per_run": (
                    len(report.lookup1_calls) + len(report.lookup2_calls)
                ),
                "lookup1_calls": len(report.lookup1_calls),
                "lookup2_calls": len(report.lookup2_calls),
                "retrieval_tokens": report.retrieval_tokens,
                "status": report.status,
            })
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-seed", action="store_true",
                        help="do not seed the golden corpus; measure "
                             "against whatever is in the DB")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--harness-runs", type=int, default=1,
                        help="harness runs per stack (default 1)")
    args = parser.parse_args(argv)

    engine = get_engine(get_settings())
    with Session(engine) as session:
        if not args.skip_seed:
            result = seed_golden_corpus(session, model=None)
            session.commit()
            print(f"golden corpus: seeded {result['seeded']} new writeups "
                  f"({result['embedded']} embedded, "
                  f"{result['total_writeups']} total rows in the set)")
        model = get_model()
        report = measure_recall(session=session, model=model)
        harness = _harness_probe(session, model, args.harness_runs)

    if args.json:
        payload = report_to_dict(report)
        payload["harness"] = harness
        print(json.dumps(payload, indent=2))
        return 0

    print_report(report)
    print("harness runs (reference loop, lab-only stub probes):")
    for run in harness:
        print(f"  {run['stack']}: wall {run['wall_ms']:.2f} ms, "
              f"queries/run {run['queries_per_run']} "
              f"(lookup1 {run['lookup1_calls']}, "
              f"lookup2 {run['lookup2_calls']}), "
              f"retrieval {run['retrieval_tokens']} tokens, "
              f"status {run['status']}")
    print("note: harness wall time is dominated by probe stub + lookups, "
          "not by the search engine alone; search p50/p95 above are the "
          "lookup latencies the <5s / <3s targets apply to.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
