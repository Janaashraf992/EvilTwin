"""
SQLAlchemy ORM models for EvilTwin platform.
"""
from sqlalchemy import Column, String, Boolean, Float, Integer, DateTime, ARRAY, ForeignKey
from sqlalchemy.dialects.postgresql import INET, UUID, JSONB
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime
import uuid

from config import CAIRO_TZ


def _now() -> datetime:
    return datetime.now(CAIRO_TZ).replace(tzinfo=None)

Base = declarative_base()

class User(Base):
    """
    Dashboard Administrator User.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    role = Column(String(20), nullable=False, default="analyst")  # admin, analyst, viewer

    created_at = Column(DateTime, nullable=False, default=_now)
    updated_at = Column(DateTime, nullable=False, default=_now, onupdate=_now)

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', is_active={self.is_active})>"



class AttackerProfile(Base):
    """
    Persistent record of an attacker IP address with geolocation,
    VPN detection, threat scoring, and behavioral fingerprint.
    """
    __tablename__ = "attacker_profiles"
    
    # Primary key: IP address
    ip = Column(INET, primary_key=True)
    
    # Geolocation data
    country = Column(String(100), nullable=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # VPN/Proxy detection
    vpn_detected = Column(Boolean, default=False, nullable=False)
    
    # Threat scoring
    threat_score = Column(Float, default=0.0, nullable=False)  # 0.0-1.0
    threat_level = Column(Integer, default=0, nullable=False)  # 0=unknown, 1=low, 2=medium, 3=high, 4=critical

    # Canary token metadata (fed to ML feature extractor, not used directly for scoring)
    canary_triggered = Column(Boolean, default=False, nullable=False)
    canary_max_difficulty = Column(Integer, default=0, nullable=False)
    canary_trigger_count = Column(Integer, default=0, nullable=False)
    cumulative_canary_score = Column(Float, default=0.0, nullable=False)  # sum of all triggered token score_values
    
    # Temporal tracking
    first_seen = Column(DateTime, nullable=False, default=_now)
    last_seen = Column(DateTime, nullable=False, default=_now, onupdate=_now)
    
    # Session tracking
    total_sessions = Column(Integer, default=0, nullable=False)
    
    # Behavioral fingerprint (SHA-256 hash)
    fingerprint_hash = Column(String(64), nullable=True)
    
    # Relationships
    sessions = relationship("SessionLog", back_populates="attacker", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="attacker", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<AttackerProfile(ip={self.ip}, threat_level={self.threat_level}, sessions={self.total_sessions})>"


class SessionLog(Base):
    """
    Complete record of an attacker's interaction with a honeypot,
    including commands, credentials, and malware samples.
    """
    __tablename__ = "session_logs"
    
    # Primary key: UUID
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign key to AttackerProfile
    attacker_ip = Column(INET, ForeignKey("attacker_profiles.ip"), nullable=False)
    
    # Session metadata
    honeypot = Column(String(50), nullable=False)  # 'cowrie', 'dionaea', 'canary'
    protocol = Column(String(20), nullable=False)  # 'ssh', 'http', 'ftp', etc.
    
    # Temporal data
    start_time = Column(DateTime, nullable=False, default=_now)
    end_time = Column(DateTime, nullable=True)
    
    # Behavioral data (JSONB for flexible structure)
    commands = Column(JSONB, default=list, nullable=False)  # [{timestamp, command, output}]
    credentials_tried = Column(JSONB, default=list, nullable=False)  # [{username, password, success}]
    
    # Malware tracking
    malware_hashes = Column(ARRAY(String), default=list, nullable=False)
    
    # Raw log preservation for forensics
    raw_log = Column(JSONB, nullable=False)
    
    # Relationships
    attacker = relationship("AttackerProfile", back_populates="sessions")
    alerts = relationship("Alert", back_populates="session", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<SessionLog(id={self.id}, attacker_ip={self.attacker_ip}, honeypot={self.honeypot}, commands={len(self.commands) if self.commands else 0})>"


class CanaryToken(Base):
    """
    A deployed canary token (honeytoken). When triggered, the token fires a
    webhook to POST /webhook/canary which creates a SessionLog with
    honeypot='canary' and an alert at the token's difficulty level.
    """
    __tablename__ = "canary_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    label = Column(String(255), nullable=False)
    description = Column(String(1000), nullable=True)
    token_kind = Column(String(50), nullable=False, default="url")  # url, file, dns, aws_key, custom
    difficulty = Column(Integer, nullable=False, default=1)  # 1=easy, 2=moderate, 3=devious
    score_value = Column(Float, nullable=False, default=0.0)  # additive threat score contribution per trigger
    created_at = Column(DateTime, nullable=False, default=_now)
    last_triggered_at = Column(DateTime, nullable=True)
    trigger_count = Column(Integer, default=0, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<CanaryToken(id={self.id}, label='{self.label}', triggers={self.trigger_count})>"


class Alert(Base):
    """
    Alert notification generated when threat level reaches high (3) or critical (4).
    Includes acknowledgment tracking for SOC workflow.
    """
    __tablename__ = "alerts"
    
    # Primary key: UUID
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    
    # Foreign keys
    session_id = Column(UUID(as_uuid=True), ForeignKey("session_logs.id"), nullable=False)
    attacker_ip = Column(INET, ForeignKey("attacker_profiles.ip"), nullable=False)
    
    # Alert metadata
    threat_level = Column(Integer, nullable=False)  # 3=high, 4=critical
    message = Column(String, nullable=False)
    
    # Temporal tracking
    created_at = Column(DateTime, nullable=False, default=_now)
    
    # Acknowledgment fields
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    
    # Relationships
    session = relationship("SessionLog", back_populates="alerts")
    attacker = relationship("AttackerProfile", back_populates="alerts")
    
    def __repr__(self):
        return f"<Alert(id={self.id}, threat_level={self.threat_level}, attacker_ip={self.attacker_ip}, acknowledged={self.acknowledged})>"
