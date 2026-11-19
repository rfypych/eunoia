"""Cross-cutting regression test (final review recommendation).

Several tests used to read files via cwd-relative paths
(``Path("docs/...")``), so the suite only passed when run from the
repo root. The path fixes (Tasks 1, 15, 16) resolve against the repo
root / the test file; this test proves it by running those tests
from a different working directory.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

_PATH_DEPENDENT_TESTS = [
    "tests/test_probe.py",
    "tests/test_dod.py",
    "tests/test_golden.py::test_golden_set_has_50_queries",
    "tests/test_golden.py::test_excluded_rows_never_served",
]


def test_suite_passes_from_another_working_directory(tmp_path):
    """Run the path-dependent tests with cwd=/tmp: they must pass
    without the repo root as the working directory.

    test_excluded_rows_never_served needs the test DB (the golden
    fixture), so the whole subset runs against eunoia_test like the
    rest of the suite.
    """
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
        + [str(REPO / node) for node in _PATH_DEPENDENT_TESTS],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, (
        "path-dependent tests failed from another cwd:\n"
        f"{proc.stdout}\n{proc.stderr}"
    )
