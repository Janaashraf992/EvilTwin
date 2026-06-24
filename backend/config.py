from datetime import datetime
from functools import lru_cache
from typing import Optional
from zoneinfo import ZoneInfo

from pydantic_settings import BaseSettings, SettingsConfigDict

CAIRO_TZ = ZoneInfo("Africa/Cairo")

REAL_HONEYPOT_TYPES = ("cowrie", "dionaea", "canary")


def cairo_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=CAIRO_TZ)
    return dt.isoformat()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")

    POSTGRES_HOST: str = "postgres"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "eviltwin"
    POSTGRES_USER: str = "eviltwin"
    POSTGRES_PASSWORD: str = "eviltwin"

    RYU_REST_URL: str = "http://ryu:8080"
    HONEYPOT_IP: str = "10.0.2.10"
    REAL_NET_CIDR: str = "10.0.1.0/24"
    THREAT_REDIRECT_THRESHOLD: int = 2

    MODEL_PATH: str = "/app/ai/model.pkl"
    PRE_SESSION_MODEL_PATH: str = "/app/ai/pre_session_model.pkl"
    SCORE_CACHE_TTL: int = 300

    IPINFO_TOKEN: str = ""
    ABUSEIPDB_API_KEY: str = ""

    SPLUNK_HEC_URL: Optional[str] = None
    SPLUNK_HEC_TOKEN: Optional[str] = None

    CANARY_WEBHOOK_SECRET: str = ""
    CANARY_WEBHOOK_TOLERANCE_SECONDS: int = 300
    # Optional JSON override for honeypot-side bait detection: {"substring": "token-uuid"}.
    # Empty string uses the built-in patterns in services/canary.py.
    CANARY_BAIT_MAP: str = ""
    # Suppress duplicate canary alerts for the same (ip, token) within this window.
    CANARY_INGEST_COOLDOWN_SECONDS: int = 30

    SECRET_KEY: str = "change-me-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # OpenAI-compatible LLM configuration
    LLM_API_KEY: Optional[str] = None
    LLM_BASE_URL: str = "https://api.openai.com/v1"
    LLM_MODEL: str = "gpt-4o-mini"
    LLM_MAX_TOKENS: int = 1024
    LLM_TEMPERATURE: float = 0.2

    VITE_API_BASE_URL: str = "http://localhost:8000"
    BACKEND_URL: str = "http://localhost:8000"
    VITE_WS_URL: str = "ws://localhost:8000/ws/alerts"

    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8000
    LOG_LEVEL: str = "INFO"
    DEBUG: bool = False

    DEMO_BOOTSTRAP: bool = False
    DEMO_USER_EMAIL: Optional[str] = None
    DEMO_USER_PASSWORD: Optional[str] = None
    DEMO_USER_ROLE: str = "analyst"

    COWRIE_TAIL_ENABLED: bool = True
    COWRIE_LOG_PATH: str = "/logs/cowrie/cowrie.json"
    DIONAEA_TAIL_ENABLED: bool = True
    DIONAEA_LOG_PATH: str = "/logs/dionaea/dionaea.json"
    HONEYPOT_LOG_POLL_INTERVAL_SECONDS: float = 1.0

    GATEWAY_WHITELIST_CIDRS: str = ""
    GATEWAY_COLLECT_WINDOW_S: float = 5.0
    PENTEST_CIDRS: str = ""
    SERVICE_ACCOUNT_USERNAME_PATTERNS: str = ""

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
