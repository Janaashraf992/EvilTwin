from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, get_settings
from database import get_db
from deps import get_current_user
from models import CanaryToken, User
from schemas import (
    CanaryTokenCreate,
    CanaryTokenListResponse,
    CanaryTokenResponse,
    CanaryWebhookRequest,
)
from services.canary import default_score_value, trigger_canary
from services.canary_webhook import validate_canary_signature
from state import app_state

router = APIRouter(tags=["canary"])


# ---------------------------------------------------------------------------
# Canary token management (authenticated)
# ---------------------------------------------------------------------------

def _token_to_response(token: CanaryToken) -> CanaryTokenResponse:
    settings = get_settings()
    backend_url = getattr(settings, "BACKEND_URL", settings.VITE_API_BASE_URL)
    webhook_url = f"{backend_url}/webhook/canary"
    sv = token.score_value if token.score_value > 0 else default_score_value(token.difficulty)
    return CanaryTokenResponse(
        id=token.id,
        label=token.label,
        description=token.description,
        token_kind=token.token_kind,
        difficulty=token.difficulty,
        score_value=sv,
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
        score_value=body.score_value if body.score_value > 0 else default_score_value(body.difficulty),
        created_at=datetime.now(CAIRO_TZ).replace(tzinfo=None),
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

    alert = await trigger_canary(
        db,
        payload.token_id,
        str(payload.src_ip),
        timestamp=payload.timestamp,
        source="webhook",
        user_agent=payload.user_agent or "",
        raw_log=payload.model_dump(mode="json"),
        runtime_state=app_state,
    )
    await db.commit()

    return {"status": "ok", "alert_id": str(alert.id) if alert else None}

