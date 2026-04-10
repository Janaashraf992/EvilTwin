"""
Pydantic schemas for request validation and response serialization.
"""

from pydantic import BaseModel, ConfigDict, IPvAnyAddress
from datetime import datetime
from uuid import UUID
from pydantic import BaseModel, ConfigDict, IPvAnyAddress, EmailStr
from datetime import datetime
from uuid import UUID
from typing import Optional, List

# --- Auth Schemas ---

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: UUID
    email: EmailStr
    is_active: bool
    role: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[UUID] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# --- Platform Schemas ---

class CommandSchema(BaseModel):
    """Schema for a command executed in a honeypot session."""
    timestamp: datetime
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
    start_time: datetime
    end_time: Optional[datetime]
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
    created_at: datetime
    acknowledged: bool
    acknowledged_by: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class StatsResponse(BaseModel):
    """Dashboard statistics and aggregations."""
    total_sessions_24h: int
    unique_attackers_24h: int
    critical_alerts_24h: int
    top_commands: List[dict]
    attacks_by_hour: List[dict]
    threat_level_distribution: List[dict]


class CanaryWebhookRequest(BaseModel):
    """Canary token webhook payload."""
    token_id: str
    timestamp: datetime
    src_ip: IPvAnyAddress
    user_agent: Optional[str] = None
    signature: str


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
