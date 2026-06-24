from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, REAL_HONEYPOT_TYPES, cairo_iso
from database import get_db
from deps import get_current_user
from models import SessionLog, User
from state import app_state

logger = logging.getLogger(__name__)

router = APIRouter(tags=["splunk"])

MAX_BATCH = 5000
DELAY_BETWEEN = 0.01


async def _sync_sessions(sessions, source_label="sync"):
    sent = 0
    failed = 0
    for i, session in enumerate(sessions):
        if i > 0 and i % 50 == 0:
            await asyncio.sleep(DELAY_BETWEEN)
        event_data = {
            "session_id": str(session.id),
            "attacker_ip": str(session.attacker_ip),
            "honeypot": session.honeypot,
            "protocol": session.protocol,
            "start_time": cairo_iso(session.start_time),
            "end_time": cairo_iso(session.end_time),
            "commands": session.commands,
            "credentials_tried": session.credentials_tried,
            "malware_hashes": session.malware_hashes,
            "raw_log": session.raw_log,
        }
        success = await app_state.splunk_forwarder.send_event(
            event_data,
            source=f"eviltwin-{source_label}-{session.honeypot}",
        )
        if success:
            sent += 1
        else:
            failed += 1
    return sent, failed


async def splunk_startup_sync(db: AsyncSession) -> int:
    if app_state.splunk_forwarder is None:
        return 0
    result = await db.execute(
        select(SessionLog)
        .where(SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES))
        .order_by(SessionLog.start_time.asc())
        .limit(MAX_BATCH)
    )
    sessions = result.scalars().all()
    if not sessions:
        logger.info("Splunk startup sync: no sessions to forward")
        return 0
    sent, failed = await _sync_sessions(sessions, source_label="startup")
    logger.info("Splunk startup sync: %d sent, %d failed (total=%d)", sent, failed, len(sessions))
    return sent


@router.post("/splunk/sync")
async def splunk_sync(
    hours: int = Query(default=0, ge=0, le=8760),
    all: bool = Query(default=False),
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> dict:
    if app_state.splunk_forwarder is None:
        raise HTTPException(status_code=503, detail="Splunk forwarder not configured")

    if all or hours <= 0:
        result = await db.execute(
            select(SessionLog)
            .where(SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES))
            .order_by(SessionLog.start_time.asc())
            .limit(MAX_BATCH)
        )
    else:
        since = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(hours=hours)
        result = await db.execute(
            select(SessionLog)
            .where(
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
                SessionLog.start_time >= since,
            )
            .order_by(SessionLog.start_time.asc())
            .limit(MAX_BATCH)
        )
    sessions = result.scalars().all()
    sent, failed = await _sync_sessions(sessions, source_label="sync")

    label = "all" if all else f"last {hours}h"
    logger.info("Splunk sync complete: %d sent, %d failed (%s)", sent, failed, label)

    return {"sent": sent, "failed": failed, "total": len(sessions), "hours": hours, "all": all}


@router.get("/splunk/status")
async def splunk_status(
    _current_user: User = Depends(get_current_user),
) -> dict:
    if app_state.splunk_forwarder is None:
        return {"configured": False, "sent": 0, "failed": 0}

    return {
        "configured": True,
        "sent": app_state.splunk_forwarder.total_sent,
        "failed": app_state.splunk_forwarder.total_failed,
        "hec_url": app_state.splunk_forwarder.hec_url,
    }
