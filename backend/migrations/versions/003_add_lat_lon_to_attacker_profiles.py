"""add lat lon to attacker profiles

Revision ID: 003
Revises: 002
Create Date: 2026-04-04

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '003'
down_revision: Union[str, Sequence[str], None] = '002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add latitude and longitude to attacker_profiles
    op.add_column('attacker_profiles', sa.Column('latitude', sa.Float(), nullable=True))
    op.add_column('attacker_profiles', sa.Column('longitude', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('attacker_profiles', 'longitude')
    op.drop_column('attacker_profiles', 'latitude')
