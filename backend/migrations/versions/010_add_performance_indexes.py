"""Add performance indexes for session_logs and attacker_profiles

Revision ID: 010
Revises: 009
Create Date: 2026-06-22
"""
from typing import Sequence, Union
from alembic import op

revision: str = "010"
down_revision: Union[str, None] = "009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_session_logs_start_time", "session_logs", ["start_time"])
    op.create_index("ix_session_logs_attacker_ip_start_time", "session_logs", ["attacker_ip", "start_time"])
    op.create_index("ix_attacker_profiles_vpn_detected", "attacker_profiles", ["vpn_detected"])


def downgrade() -> None:
    op.drop_index("ix_attacker_profiles_vpn_detected", table_name="attacker_profiles")
    op.drop_index("ix_session_logs_attacker_ip_start_time", table_name="session_logs")
    op.drop_index("ix_session_logs_start_time", table_name="session_logs")
