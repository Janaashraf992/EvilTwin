"""
Pydantic schemas for request validation and response serialization.
"""

from datetime import datetime
from typing import Annotated, Optional, List
from uuid import UUID

from pydantic import BaseModel, ConfigDict, IPvAnyAddress, PlainSerializer

from config import CAIRO_TZ


def _serialize_cairo(dt: datetime) -> str:
    """Serialize datetimes in DST-aware Africa/Cairo local time.

    Naive values are assumed to already be Cairo wall-clock; aware values are
    converted. This guarantees every API timestamp carries the correct Cairo
    offset (+03:00 in summer, +02:00 in winter) instead of an ambiguous bare
    timestamp the frontend would have to guess at.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=CAIRO_TZ)
    else:
        dt = dt.astimezone(CAIRO_TZ)
    return dt.isoformat()


CairoDateTime = Annotated[
    datetime,
    PlainSerializer(_serialize_cairo, return_type=str, when_used="json"),
]

# --- Auth Schemas ---

class UserCreate(BaseModel):
    email: str
    password: str

class UserResponse(BaseModel):
    id: UUID
    email: str
    is_active: bool
    role: str
    created_at: CairoDateTime
    updated_at: CairoDateTime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserUpdate(BaseModel):
    email: Optional[str] = None
    current_password: Optional[str] = None
    new_password: Optional[str] = None

class TokenData(BaseModel):
    user_id: Optional[UUID] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class LoginRequest(BaseModel):
    email: str
    password: str

# --- Platform Schemas ---

class CommandSchema(BaseModel):
    """Schema for a command executed in a honeypot session."""
    timestamp: CairoDateTime
    command: str
    output: Optional[str] = None


class CredentialSchema(BaseModel):
    """Schema for credential attempts during authentication."""
    username: str
    password: str
    success: bool = False


class LogIngestRequest(BaseModel):
    """Schema for incoming Cowrie JSON log events."""
    eventid: str
    src_ip: IPvAnyAddress
    src_port: int
    dst_ip: IPvAnyAddress
    dst_port: int
    session: str
    protocol: str
    timestamp: datetime
    message: Optional[str] = None
    input: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


class LogIngestResponse(BaseModel):
    """Response after log ingestion with threat assessment."""
    session_id: UUID
    threat_score: float
    threat_level: int


class ScoreResponse(BaseModel):
    """Response for threat score queries."""
    ip: str
    threat_score: float
    threat_level: int
    vpn_detected: bool


class SessionResponse(BaseModel):
    """Complete session details with all commands and credentials."""
    id: UUID
    attacker_ip: str
    honeypot: str
    protocol: str
    start_time: CairoDateTime
    end_time: Optional[CairoDateTime]
    commands: List[CommandSchema]
    credentials_tried: List[CredentialSchema]
    malware_hashes: List[str]
    raw_log: dict
    threat_score: float = 0.0
    threat_level: int = 0
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    vpn_detected: bool = False

    model_config = ConfigDict(from_attributes=True)


class SessionListResponse(BaseModel):
    """Paginated list of sessions."""
    items: List[SessionResponse]
    total: int
    page: int
    pages: int


class AlertResponse(BaseModel):
    """Alert details for high-threat events."""
    id: UUID
    session_id: UUID
    attacker_ip: str
    threat_level: int
    message: str
    created_at: CairoDateTime
    acknowledged: bool
    acknowledged_by: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class StatsResponse(BaseModel):
    """Dashboard statistics and aggregations."""
    total_sessions_24h: int
    unique_attackers_24h: int
    critical_alerts_24h: int
    canary_triggers_24h: int
    vpn_users_count: int
    honeypot_breakdown: List[dict]  # [{honeypot, count}]
    top_commands: List[dict]
    attacks_by_hour: List[dict]
    threat_level_distribution: List[dict]


class CanaryWebhookRequest(BaseModel):
    """Canary token webhook payload."""
    token_id: str
    timestamp: datetime
    src_ip: IPvAnyAddress
    user_agent: Optional[str] = None
    nonce: Optional[str] = None  # unique per request; keeps signatures distinct for replay protection
    signature: str


class CanaryTokenCreate(BaseModel):
    """Request body to create a new canary token."""
    label: str
    description: Optional[str] = None
    token_kind: str = "url"  # url, file, dns, aws_key, custom
    difficulty: int = 1  # 1=easy, 2=moderate, 3=devious
    score_value: float = 0.0  # how much threat score this token adds when triggered (0.0 - 1.0)


class CanaryTokenResponse(BaseModel):
    """Canary token details returned by the API."""
    id: UUID
    label: str
    description: Optional[str]
    token_kind: str
    difficulty: int
    score_value: float
    created_at: CairoDateTime
    last_triggered_at: Optional[CairoDateTime]
    trigger_count: int
    is_active: bool
    webhook_url: str  # computed field — the URL to configure in canarytokens.org or similar

    model_config = ConfigDict(from_attributes=True)


class CanaryTokenListResponse(BaseModel):
    """Paginated list of canary tokens."""
    items: List[CanaryTokenResponse]
    total: int


# --- LLM / AI Analysis Schemas ---

class ThreatAnalysisRequest(BaseModel):
    """Request for AI-powered threat analysis of a session."""
    session_id: UUID
    context: Optional[str] = None

class ThreatAnalysisResponse(BaseModel):
    """AI-generated threat analysis result."""
    session_id: UUID
    summary: str
    risk_assessment: str
    recommended_actions: List[str]
    ioc_indicators: List[str]
    ttps: List[str]
    confidence: float
    model_used: str

class ChatRequest(BaseModel):
    """Request for conversational threat intelligence queries."""
    message: str
    session_id: Optional[UUID] = None
    conversation_history: Optional[List[dict]] = None

class ChatResponse(BaseModel):
    """Response from the AI threat analyst."""
    reply: str
    model_used: str
    tokens_used: int


# --- Gateway Pre-Screen Schemas ---

class GatewayScoreRequest(BaseModel):
    src_ip: str
    src_port: int
    client_version: str = ""
    kex_algorithms_hash: str = ""
    time_to_first_auth: float = 0.0
    auth_attempts_count: int = 0
    auth_methods_used: list[str] = []
    usernames_tried: list[str] = []
    passwords_tried: list[str] = []
    public_key_attempted: bool = False
    shell_requested: bool = False
    exec_command: Optional[str] = None
    is_interactive: bool = False
    auth_attempt_interval: float = 0.0


class GatewayScoreResponse(BaseModel):
    decision: str  # "real" or "honeypot"
    confidence: float
    reason: str
    user_type: str = "unknown"
    ml_level: int = -1
    ml_confidence: float = 0.0
    llm_used: bool = False
    llm_explanation: str = ""
