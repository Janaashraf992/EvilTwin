"""add canary_tokens table

Revision ID: 005
Revises: 004
Create Date: 2026-05-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID


# revision identifiers, used by Alembic.
revision: str = '005'
down_revision: Union[str, Sequence[str], None] = '004'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'canary_tokens',
        sa.Column('id', UUID(as_uuid=True), primary_key=True),
        sa.Column('label', sa.String(length=255), nullable=False),
        sa.Column('description', sa.String(length=1000), nullable=True),
        sa.Column('token_kind', sa.String(length=50), nullable=False, server_default='url'),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_triggered_at', sa.DateTime(), nullable=True),
        sa.Column('trigger_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
    )
    op.create_index('idx_canary_tokens_active', 'canary_tokens', ['is_active'])


def downgrade() -> None:
    op.drop_index('idx_canary_tokens_active', table_name='canary_tokens')
    op.drop_table('canary_tokens')
