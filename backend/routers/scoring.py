from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from deps import get_current_user
from models import AttackerProfile, User
from schemas import ScoreResponse
from state import app_state

router = APIRouter(prefix="/score", tags=["scoring"])


@router.get("/{ip}", response_model=ScoreResponse)
async def get_score(
    ip: str,
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> ScoreResponse:
    try:
        parsed_ip = str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid IP address") from exc

    profile = await db.get(AttackerProfile, parsed_ip)
    if profile:
        return ScoreResponse(
            ip=parsed_ip,
            threat_score=profile.threat_score,
            threat_level=profile.threat_level,
            vpn_detected=profile.vpn_detected,
        )

    vpn_detected = False
    if app_state.vpn_detector:
        result = await app_state.vpn_detector.check(parsed_ip)
        vpn_detected = result.vpn or result.proxy or result.tor

    return ScoreResponse(ip=parsed_ip, threat_score=0.0, threat_level=0, vpn_detected=vpn_detected)
