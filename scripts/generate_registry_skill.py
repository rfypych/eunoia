"""Regenerate the packaged registry skill.

Writes ``src/eunoia/skills_data/eunoia-registry/SKILL.md`` from
``eunoia.skills.get_registry_skill``. The file is checked into the
repo and shipped as package data, so ``eunoia skills install`` can
install it without a network call; ``tests/test_installable_skills.py``
pins the packaged file byte-identical to the generator, so run this
script whenever the generator changes::

    .venv/bin/python scripts/generate_registry_skill.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from eunoia.skills import get_registry_skill  # noqa: E402


def main() -> int:
    target = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "eunoia"
        / "skills_data"
        / "eunoia-registry"
        / "SKILL.md"
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(get_registry_skill())
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
