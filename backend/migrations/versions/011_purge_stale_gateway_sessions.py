"""Purge stale gateway bookkeeping rows from session_logs

The SSH gateway writes transient session_logs rows with honeypot='gateway'
purely for pass-1/pass-2 classification and reconnect/session-reuse tracking.
These are not real honeypot interactions and must never surface in the
dashboard or Splunk. This migration removes already-accumulated stale rows
(older than 5 minutes, matching the gateway's own cleanup window). Active
rows inside the reconnect window are preserved so in-flight routing is
unaffected.

Revision ID: 011
Revises: 010
Create Date: 2026-06-24
"""
from datetime import datetime, timedelta
from typing import Sequence, Union
from zoneinfo import ZoneInfo

import sqlalchemy as sa
from alembic import op

revision: str = "011"
down_revision: Union[str, None] = "010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CAIRO_TZ = ZoneInfo("Africa/Cairo")


def upgrade() -> None:
    cutoff = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(minutes=5)
    op.execute(
        sa.text(
            "DELETE FROM session_logs "
            "WHERE honeypot = 'gateway' AND start_time < :cutoff"
        ).bindparams(cutoff=cutoff)
    )


def downgrade() -> None:
    pass
