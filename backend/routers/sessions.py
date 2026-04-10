from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from deps import get_current_user
from models import AttackerProfile, SessionLog, User
from schemas import SessionListResponse, SessionResponse

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("", response_model=SessionListResponse)
async def list_sessions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    threat_level: Optional[int] = None,
    honeypot: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    ip: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
):
    filters = []
    if threat_level is not None:
        filters.append(AttackerProfile.threat_level == threat_level)
    if honeypot:
        filters.append(SessionLog.honeypot == honeypot)
    if date_from:
        filters.append(SessionLog.start_time >= date_from)
    if date_to:
        filters.append(SessionLog.start_time <= date_to)
    if ip:
        filters.append(SessionLog.attacker_ip == ip)

    where_clause = and_(*filters) if filters else None

    count_query = (
        select(func.count())
        .select_from(SessionLog)
        .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
    )
    if where_clause is not None:
        count_query = count_query.where(where_clause)

    total = (await db.execute(count_query)).scalar_one()
    pages = max((total + page_size - 1) // page_size, 1)

    query = (
        select(SessionLog, AttackerProfile)
        .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
        .order_by(SessionLog.start_time.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    if where_clause is not None:
        query = query.where(where_clause)

    rows = (await db.execute(query)).all()
    items = [
        SessionResponse(
            id=session.id,
            attacker_ip=str(session.attacker_ip),
            honeypot=session.honeypot,
            protocol=session.protocol,
            start_time=session.start_time,
            end_time=session.end_time,
            commands=session.commands or [],
            credentials_tried=session.credentials_tried or [],
            malware_hashes=session.malware_hashes or [],
            raw_log=session.raw_log or {},
            threat_score=profile.threat_score,
            threat_level=profile.threat_level,
            country=profile.country,
            city=profile.city,
            isp=profile.isp,
            vpn_detected=profile.vpn_detected,
        )
        for session, profile in rows
    ]

    return SessionListResponse(items=items, total=total, page=page, pages=pages)


@router.get("/{session_id}", response_model=SessionResponse)
async def get_session(
    session_id: UUID,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> SessionResponse:
    query = (
        select(SessionLog, AttackerProfile)
        .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
        .where(SessionLog.id == session_id)
    )
    row = (await db.execute(query)).first()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    session, profile = row
    return SessionResponse(
        id=session.id,
        attacker_ip=str(session.attacker_ip),
        honeypot=session.honeypot,
        protocol=session.protocol,
        start_time=session.start_time,
        end_time=session.end_time,
        commands=session.commands or [],
        credentials_tried=session.credentials_tried or [],
        malware_hashes=session.malware_hashes or [],
        raw_log=session.raw_log or {},
        threat_score=profile.threat_score,
        threat_level=profile.threat_level,
        country=profile.country,
        city=profile.city,
        isp=profile.isp,
        vpn_detected=profile.vpn_detected,
    )
