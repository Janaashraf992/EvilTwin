"""add cumulative_canary_score column to attacker_profiles

Revision ID: 009
Revises: 008
Create Date: 2026-06-19
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "009"
down_revision: Union[str, None] = "008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "attacker_profiles",
        sa.Column("cumulative_canary_score", sa.Float(), nullable=False, server_default="0.0"),
    )


def downgrade() -> None:
    op.drop_column("attacker_profiles", "cumulative_canary_score")
