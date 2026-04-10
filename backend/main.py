from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from config import get_settings
from database import close_db, get_db_context, init_db
from routers import alerts, canary, dashboard, health, ingest, scoring, sessions, auth
from routers import ai as ai_router
from state import app_state


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    init_db(settings.database_url)
    app_state.started_at = datetime.now(timezone.utc)

    # Services initialize lazily, but model loading is attempted on startup.
    from services.threat_scorer import ThreatScorer
    from services.vpn_detection import VPNDetector
    from services.splunk_forwarder import SplunkForwarder
    from services.llm_service import LLMService

    app_state.threat_scorer = ThreatScorer(settings.MODEL_PATH, settings.SCORE_CACHE_TTL)
    app_state.vpn_detector = VPNDetector(settings.IPINFO_TOKEN, settings.ABUSEIPDB_API_KEY)

    if settings.SPLUNK_HEC_URL and settings.SPLUNK_HEC_TOKEN:
        app_state.splunk_forwarder = SplunkForwarder(
            settings.SPLUNK_HEC_URL, settings.SPLUNK_HEC_TOKEN
        )

    if settings.LLM_API_KEY:
        app_state.llm_service = LLMService(
            api_key=settings.LLM_API_KEY,
            base_url=settings.LLM_BASE_URL,
            model=settings.LLM_MODEL,
            max_tokens=settings.LLM_MAX_TOKENS,
            temperature=settings.LLM_TEMPERATURE,
        )

    async with get_db_context() as db:
        await db.execute(text("SELECT 1"))

    try:
        yield
    finally:
        if app_state.vpn_detector is not None:
            await app_state.vpn_detector.close()
            app_state.vpn_detector = None

        if app_state.splunk_forwarder is not None:
            await app_state.splunk_forwarder.close()
            app_state.splunk_forwarder = None

        if app_state.llm_service is not None:
            await app_state.llm_service.close()
            app_state.llm_service = None

        await close_db()


settings = get_settings()
app = FastAPI(title="EvilTwin Backend API", version="0.2.0", lifespan=lifespan)

allowed_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(sessions.router)
app.include_router(scoring.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(canary.router)
app.include_router(ai_router.router)
