import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from config import get_settings
from database import close_db, get_db_context, init_db
from routers import alerts, canary, dashboard, health, ingest, scoring, sessions, auth
from routers import ai as ai_router
from services.cowrie import watch_cowrie_log
from services.dionaea import watch_dionaea_log
from state import app_state


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    init_db(settings.database_url)
    app_state.started_at = datetime.now(timezone.utc)
    background_tasks: list[asyncio.Task[None]] = []

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

    if settings.COWRIE_TAIL_ENABLED:
        background_tasks.append(
            asyncio.create_task(
                watch_cowrie_log(
                    settings.COWRIE_LOG_PATH,
                    settings.HONEYPOT_IP,
                    poll_interval_seconds=settings.HONEYPOT_LOG_POLL_INTERVAL_SECONDS,
                )
            )
        )

    if settings.DIONAEA_TAIL_ENABLED:
        background_tasks.append(
            asyncio.create_task(
                watch_dionaea_log(
                    settings.DIONAEA_LOG_PATH,
                    settings.HONEYPOT_IP,
                    poll_interval_seconds=settings.HONEYPOT_LOG_POLL_INTERVAL_SECONDS,
                )
            )
        )

    try:
        yield
    finally:
        for task in background_tasks:
            task.cancel()
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

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

_raw_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
# If the only origins listed are the default localhost entries, allow all origins
# so the dashboard works from any LAN browser without extra configuration.
_localhost_only = all(
    o.startswith("http://localhost") or o.startswith("https://localhost")
    for o in _raw_origins
)
if _localhost_only:
    allowed_origins = ["*"]
    _allow_credentials = False  # credentials cannot be used with wildcard origin
else:
    allowed_origins = _raw_origins
    _allow_credentials = True

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=None if allowed_origins == ["*"] else settings.CORS_ORIGIN_REGEX or None,
    allow_credentials=_allow_credentials,
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
