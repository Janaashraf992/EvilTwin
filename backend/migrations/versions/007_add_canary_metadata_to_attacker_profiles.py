"""add canary metadata columns to attacker_profiles

Revision ID: 007
Revises: 006
Create Date: 2026-06-14
"""

from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "007"
down_revision: Union[str, None] = "006"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "attacker_profiles",
        sa.Column("canary_triggered", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.add_column(
        "attacker_profiles",
        sa.Column("canary_max_difficulty", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "attacker_profiles",
        sa.Column("canary_trigger_count", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("attacker_profiles", "canary_trigger_count")
    op.drop_column("attacker_profiles", "canary_max_difficulty")
    op.drop_column("attacker_profiles", "canary_triggered")
