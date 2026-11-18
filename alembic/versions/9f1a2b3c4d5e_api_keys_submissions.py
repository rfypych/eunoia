"""API keys + submissions tables (Task 10, spec §5.5).

Revision ID: 9f1a2b3c4d5e
Revises: 3a7b1c9d4e5f
Create Date: 2026-11-18 23:50:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9f1a2b3c4d5e'
down_revision: Union[str, Sequence[str], None] = '3a7b1c9d4e5f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'api_keys',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('key_hash', sa.String(length=64), nullable=False),
        sa.Column('owner', sa.String(length=256), nullable=True),
        sa.Column('tier', sa.String(length=32), nullable=False,
                  server_default='free'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=False,
                  server_default='false'),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('key_hash'),
    )
    op.create_table(
        'submissions',
        sa.Column('id', sa.Uuid(), nullable=False),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('status', sa.String(length=32), nullable=False,
                  server_default='in_review'),
        sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('submissions')
    op.drop_table('api_keys')
