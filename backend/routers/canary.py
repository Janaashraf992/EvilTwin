from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_settings
from database import get_db
from deps import get_current_user
from models import Alert, AttackerProfile, CanaryToken, SessionLog, User
from schemas import (
    CanaryTokenCreate,
    CanaryTokenListResponse,
    CanaryTokenResponse,
    CanaryWebhookRequest,
)
from services.canary_webhook import validate_canary_signature
from state import app_state

router = APIRouter(tags=["canary"])

# ---------------------------------------------------------------------------
# Canary token management (authenticated)
# ---------------------------------------------------------------------------

def _token_to_response(token: CanaryToken) -> CanaryTokenResponse:
    settings = get_settings()
    # Build the webhook URL analysts can paste into canarytokens.org or similar
    # The token_id field in the payload should equal str(token.id)
    webhook_url = f"{settings.VITE_API_BASE_URL}/webhook/canary"
    return CanaryTokenResponse(
        id=token.id,
        label=token.label,
        description=token.description,
        token_kind=token.token_kind,
        difficulty=token.difficulty,
        created_at=token.created_at,
        last_triggered_at=token.last_triggered_at,
        trigger_count=token.trigger_count,
        is_active=token.is_active,
        webhook_url=webhook_url,
    )


@router.get("/canary/tokens", response_model=CanaryTokenListResponse)
async def list_canary_tokens(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> CanaryTokenListResponse:
    """List all deployed canary tokens ordered by creation date."""
    rows = (
        await db.execute(select(CanaryToken).order_by(CanaryToken.created_at.desc()))
    ).scalars().all()
    total = (await db.execute(select(func.count(CanaryToken.id)))).scalar_one()
    return CanaryTokenListResponse(
        items=[_token_to_response(t) for t in rows],
        total=total,
    )


@router.post("/canary/tokens", response_model=CanaryTokenResponse, status_code=201)
async def create_canary_token(
    body: CanaryTokenCreate,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> CanaryTokenResponse:
    """Create and register a new canary token."""
    token = CanaryToken(
        id=uuid.uuid4(),
        label=body.label,
        description=body.description,
        token_kind=body.token_kind,
        difficulty=body.difficulty,
        created_at=datetime.now(timezone.utc).replace(tzinfo=None),
        trigger_count=0,
        is_active=True,
    )
    db.add(token)
    await db.commit()
    await db.refresh(token)
    return _token_to_response(token)


@router.delete("/canary/tokens/{token_id}")
async def delete_canary_token(
    token_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> Response:
    """Deactivate (soft-delete) a canary token."""
    token = await db.get(CanaryToken, token_id)
    if token is None:
        raise HTTPException(status_code=404, detail="Token not found")
    token.is_active = False
    await db.commit()
    return Response(status_code=204)


# ---------------------------------------------------------------------------
# Webhook ingest (public endpoint, HMAC-authenticated)
# ---------------------------------------------------------------------------

@router.post("/webhook/canary")
async def ingest_canary(
    payload: CanaryWebhookRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_signature: str | None = Header(default=None, alias="X-Signature"),
):
    signature = x_signature or payload.signature
    body = await request.body()
    settings = get_settings()
    if not validate_canary_signature(
        body,
        signature,
        settings.CANARY_WEBHOOK_SECRET,
        timestamp=payload.timestamp.timestamp(),
        tolerance_seconds=settings.CANARY_WEBHOOK_TOLERANCE_SECONDS,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Update trigger stats on the registered token if it exists
    token_id_str = payload.token_id
    registered_token = None
    try:
        token_uuid = uuid.UUID(token_id_str)
        registered_token = await db.get(CanaryToken, token_uuid)
        if registered_token is not None:
            registered_token.trigger_count = (registered_token.trigger_count or 0) + 1
            registered_token.last_triggered_at = datetime.now(timezone.utc).replace(tzinfo=None)
    except (ValueError, AttributeError):
        pass  # token_id is not a UUID — external token, proceed normally

    threat_level = registered_token.difficulty if registered_token is not None else 3

    ip = str(payload.src_ip)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    profile = await db.get(AttackerProfile, ip)
    if profile is None:
        profile = AttackerProfile(
            ip=ip,
            first_seen=now,
            last_seen=now,
            total_sessions=1,
        )
        db.add(profile)
    else:
        profile.last_seen = now
        profile.total_sessions = (profile.total_sessions or 0) + 1

    diff = registered_token.difficulty if registered_token is not None else 3
    profile.canary_triggered = True
    profile.canary_max_difficulty = max(profile.canary_max_difficulty or 0, diff)
    profile.canary_trigger_count = (profile.canary_trigger_count or 0) + 1

    session = SessionLog(
        id=uuid.uuid4(),
        attacker_ip=ip,
        honeypot="canary",
        protocol="http",
        start_time=payload.timestamp.replace(tzinfo=None),
        end_time=payload.timestamp.replace(tzinfo=None),
        commands=[],
        credentials_tried=[],
        malware_hashes=[],
        raw_log=payload.model_dump(mode="json"),
    )
    db.add(session)
    await db.flush()

    if app_state.threat_scorer:
        score, level = await app_state.threat_scorer.score(
            session, profile, multi_protocol=False, known_bad_ip=bool(profile.vpn_detected)
        )
    else:
        score, level = 0.0, 0

    profile.threat_score = max(score, profile.threat_score or 0.0)
    profile.threat_level = max(level, profile.threat_level or 0)
    await db.flush()

    alert = Alert(
        session_id=session.id,
        attacker_ip=ip,
        threat_level=level,
        message=f"Canary token triggered: {payload.token_id}",
    )
    db.add(alert)
    await db.flush()
    await db.commit()

    alert_data = {
        "id": str(alert.id),
        "session_id": str(session.id),
        "attacker_ip": ip,
        "threat_level": alert.threat_level,
        "message": alert.message,
        "created_at": alert.created_at.isoformat() if alert.created_at else datetime.now(timezone.utc).isoformat(),
        "acknowledged": False,
    }

    await app_state.alert_manager.broadcast(alert_data)

    if app_state.splunk_forwarder:
        await app_state.splunk_forwarder.send_event(
            {**alert_data, "raw_log": payload.model_dump(mode="json")},
            source="eviltwin-canary",
        )

    return {"status": "ok", "alert_id": str(alert.id)}

