"""HNSW index on embeddings.embedding (Task 8, spec §5.7)

Revision ID: 3a7b1c9d4e5f
Revises: 7d19df2e413d
Create Date: 2026-11-18 22:42:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '3a7b1c9d4e5f'
down_revision: Union[str, Sequence[str], None] = '7d19df2e413d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute(
        "CREATE INDEX ix_embeddings_embedding_hnsw "
        "ON embeddings USING hnsw (embedding halfvec_cosine_ops) "
        "WITH (m = 16, ef_construction = 64)"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP INDEX ix_embeddings_embedding_hnsw")
