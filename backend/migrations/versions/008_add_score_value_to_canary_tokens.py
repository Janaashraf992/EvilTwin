"""add score_value column to canary_tokens

Revision ID: 008
Revises: 007
Create Date: 2026-06-19
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "008"
down_revision: Union[str, None] = "007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "canary_tokens",
        sa.Column("score_value", sa.Float(), nullable=False, server_default="0.0"),
    )


def downgrade() -> None:
    op.drop_column("canary_tokens", "score_value")
