"""Append-only audit trigger on writeup_events (Task 13, spec §6.5).

Revision ID: b7c8d9e0f1a2
Revises: 9f1a2b3c4d5e
Create Date: 2026-11-18 23:55:00.000000

"""

from typing import Sequence, Union

from alembic import op

# The trigger SQL is inlined here (final review triage, Task 13):
# a migration must not import app code — the SQL it applies has to
# be self-contained, as migration 0006 already is. The same literal
# stays in eunoia.safety.audit (APPEND_ONLY_TRIGGER_SQL) for tests.
APPEND_ONLY_TRIGGER_SQL = """
CREATE OR REPLACE FUNCTION eunoia_prevent_writeup_events_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'writeup_events is append-only: % is not allowed', TG_OP;
    RETURN NULL;
END;
$$;
DROP TRIGGER IF EXISTS writeup_events_append_only ON writeup_events;
CREATE TRIGGER writeup_events_append_only
BEFORE UPDATE OR DELETE ON writeup_events
FOR EACH ROW EXECUTE FUNCTION eunoia_prevent_writeup_events_mutation();
"""


# revision identifiers, used by Alembic.
revision: str = 'b7c8d9e0f1a2'
down_revision: Union[str, Sequence[str], None] = '9f1a2b3c4d5e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(APPEND_ONLY_TRIGGER_SQL)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TRIGGER IF EXISTS writeup_events_append_only "
               "ON writeup_events")
    op.execute("DROP FUNCTION IF EXISTS "
               "eunoia_prevent_writeup_events_mutation()")
