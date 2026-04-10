"""Create initial tables for attacker profiles, session logs, and alerts

Revision ID: 001
Revises: 
Create Date: 2026

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create attacker_profiles table
    op.create_table(
        'attacker_profiles',
        sa.Column('ip', postgresql.INET(), nullable=False),
        sa.Column('country', sa.String(length=100), nullable=True),
        sa.Column('city', sa.String(length=100), nullable=True),
        sa.Column('isp', sa.String(length=255), nullable=True),
        sa.Column('vpn_detected', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('threat_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('threat_level', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('first_seen', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('last_seen', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('total_sessions', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('fingerprint_hash', sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint('ip')
    )
    
    # Create session_logs table
    op.create_table(
        'session_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('attacker_ip', postgresql.INET(), nullable=False),
        sa.Column('honeypot', sa.String(length=50), nullable=False),
        sa.Column('protocol', sa.String(length=20), nullable=False),
        sa.Column('start_time', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('end_time', sa.DateTime(), nullable=True),
        sa.Column('commands', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('credentials_tried', postgresql.JSONB(astext_type=sa.Text()), nullable=False, server_default='[]'),
        sa.Column('malware_hashes', postgresql.ARRAY(sa.String()), nullable=False, server_default='{}'),
        sa.Column('raw_log', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(['attacker_ip'], ['attacker_profiles.ip'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create alerts table
    op.create_table(
        'alerts',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('session_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('attacker_ip', postgresql.INET(), nullable=False),
        sa.Column('threat_level', sa.Integer(), nullable=False),
        sa.Column('message', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.text('now()')),
        sa.Column('acknowledged', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('acknowledged_by', sa.String(length=100), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['attacker_ip'], ['attacker_profiles.ip'], ),
        sa.ForeignKeyConstraint(['session_id'], ['session_logs.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for attacker_profiles
    op.create_index('idx_threat_level', 'attacker_profiles', ['threat_level'])
    op.create_index('idx_last_seen', 'attacker_profiles', ['last_seen'])
    
    # Create indexes for session_logs
    op.create_index('idx_session_attacker', 'session_logs', ['attacker_ip'])
    op.create_index('idx_session_time', 'session_logs', [sa.text('start_time DESC')])
    op.create_index('idx_session_honeypot', 'session_logs', ['honeypot'])
    op.create_index('idx_commands_gin', 'session_logs', ['commands'], postgresql_using='gin')
    
    # Create indexes for alerts
    op.create_index('idx_alert_created', 'alerts', [sa.text('created_at DESC')])
    op.create_index('idx_alert_level', 'alerts', ['threat_level'])
    op.create_index('idx_alert_ack', 'alerts', ['acknowledged'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes for alerts
    op.drop_index('idx_alert_ack', table_name='alerts')
    op.drop_index('idx_alert_level', table_name='alerts')
    op.drop_index('idx_alert_created', table_name='alerts')
    
    # Drop indexes for session_logs
    op.drop_index('idx_commands_gin', table_name='session_logs')
    op.drop_index('idx_session_honeypot', table_name='session_logs')
    op.drop_index('idx_session_time', table_name='session_logs')
    op.drop_index('idx_session_attacker', table_name='session_logs')
    
    # Drop indexes for attacker_profiles
    op.drop_index('idx_last_seen', table_name='attacker_profiles')
    op.drop_index('idx_threat_level', table_name='attacker_profiles')
    
    # Drop tables
    op.drop_table('alerts')
    op.drop_table('session_logs')
    op.drop_table('attacker_profiles')
