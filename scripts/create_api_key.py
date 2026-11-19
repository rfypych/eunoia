#!/usr/bin/env python3
"""Provision one Eunoia API key (Task 16; Task 10 minor).

Creates a key via the library :func:`eunoia.api.auth.create_api_key`
and prints the plaintext ONCE — it is stored only as a SHA-256 hash
and can never be recovered from the database afterwards. Run from the
repo root with the venv, with ``DATABASE_URL`` pointing at the target
database:

    DATABASE_URL=postgresql://eunoia@localhost/eunoia \\
        .venv/bin/python scripts/create_api_key.py --owner alice

There is deliberately no HTTP admin route for this: key provisioning
is an operator action, not an API surface.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from sqlalchemy.orm import Session

from eunoia.api.auth import create_api_key
from eunoia.config import get_settings
from eunoia.db import get_engine


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(
        prog="create_api_key",
        description="Provision one Eunoia API key (printed once).")
    parser.add_argument("--owner", default=None,
                        help="Owner label recorded on the key row.")
    parser.add_argument("--tier", default="free",
                        help="Tier for the key (default: free).")
    args = parser.parse_args(argv)

    engine = get_engine(get_settings())
    with Session(engine) as session:
        plaintext, row = create_api_key(
            session, owner=args.owner, tier=args.tier)
        session.commit()
        # Read the scalars before the session closes: after commit the
        # row's attributes are expired, and reading them on a detached
        # instance raises DetachedInstanceError.
        key_id, owner, tier = row.id, row.owner, row.tier
    print(f"API key (show once, never stored): {plaintext}")
    print(f"key_id: {key_id}  owner: {owner or '-'}  tier: {tier}")


if __name__ == "__main__":
    main()
