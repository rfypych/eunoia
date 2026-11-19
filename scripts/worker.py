#!/usr/bin/env python3
"""Eunoia deployment worker — thin CLI entry point (Task 16).

Real logic lives in :mod:`eunoia.worker`; this script only exists so
supervisord/cron can run ``python scripts/worker.py poll-loop``.
Run from the repo root with the venv: ``.venv/bin/python
scripts/worker.py poll-loop``.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from eunoia.worker import main

if __name__ == "__main__":
    main()
