from __future__ import annotations

import ipaddress

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from database import get_db
from models import AttackerProfile
from schemas import GatewayScoreRequest, GatewayScoreResponse, ScoreResponse
from state import app_state

router = APIRouter(prefix="/score", tags=["scoring"])


@router.get("/{ip}", response_model=ScoreResponse)
async def get_score(
    ip: str,
    db: AsyncSession = Depends(get_db),
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


@router.post("/initial", response_model=GatewayScoreResponse)
async def score_initial(
    payload: GatewayScoreRequest,
    db: AsyncSession = Depends(get_db),
    x_gateway_attempt: str = Header(default="1", alias="X-Gateway-Attempt"),
) -> GatewayScoreResponse:
    from services.gateway_scorer import classify_connection

    attempt = int(x_gateway_attempt) if x_gateway_attempt in ("1", "2") else 1
    result = await classify_connection(payload, attempt=attempt, db=db)
    return GatewayScoreResponse(**result)
