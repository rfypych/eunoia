"""add quality_passed to writeups (Task 16, spec §6.5)

Revision ID: e6f7a8b9c0d1
Revises: b7c8d9e0f1a2
Create Date: 2026-11-19 00:45:00.000000

Quality-gate verdict on the writeup row itself (nullable: None means
not yet gated and stays servable; False quarantines the record via
the shared serving gate until a human clears it). Self-contained:
no application-code imports (see the Task 13 review minor on
migration 0005).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, Sequence[str], None] = 'b7c8d9e0f1a2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('writeups', sa.Column('quality_passed', sa.Boolean(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('writeups', 'quality_passed')
