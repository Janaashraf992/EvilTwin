from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import Alert, AttackerProfile, SessionLog
from schemas import CanaryWebhookRequest
from services.canary_webhook import validate_canary_signature
from state import app_state

router = APIRouter(prefix="/webhook", tags=["canary"])


@router.post("/canary")
async def ingest_canary(
    payload: CanaryWebhookRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_signature: str | None = Header(default=None, alias="X-Signature"),
):
    signature = x_signature or payload.signature
    body = await request.body()
    from config import get_settings

    settings = get_settings()
    if not validate_canary_signature(
        body,
        signature,
        settings.CANARY_WEBHOOK_SECRET,
        timestamp=payload.timestamp.timestamp(),
        tolerance_seconds=settings.CANARY_WEBHOOK_TOLERANCE_SECONDS,
    ):
        raise HTTPException(status_code=401, detail="Invalid signature")

    ip = str(payload.src_ip)
    profile = await db.get(AttackerProfile, ip)
    if profile is None:
        profile = AttackerProfile(ip=ip, first_seen=datetime.utcnow(), last_seen=datetime.utcnow(), total_sessions=1)
        db.add(profile)

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

    alert = Alert(
        session_id=session.id,
        attacker_ip=ip,
        threat_level=3,
        message=f"Canary token triggered: {payload.token_id}",
    )
    db.add(alert)
    await db.flush()

    await app_state.alert_manager.broadcast(
        {
            "id": str(alert.id),
            "session_id": str(session.id),
            "attacker_ip": ip,
            "threat_level": alert.threat_level,
            "message": alert.message,
            "created_at": alert.created_at.isoformat() if alert.created_at else datetime.utcnow().isoformat(),
            "acknowledged": False,
        }
    )

    return {"status": "ok", "alert_id": str(alert.id)}
