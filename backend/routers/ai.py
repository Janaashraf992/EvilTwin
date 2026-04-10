"""
AI-powered threat analysis endpoints using OpenAI-compatible LLM.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from deps import get_current_user, get_db
from models import AttackerProfile, SessionLog, User
from schemas import (
    ChatRequest,
    ChatResponse,
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
)
from state import app_state

router = APIRouter(prefix="/ai", tags=["ai"])


def _require_llm() -> None:
    if app_state.llm_service is None:
        raise HTTPException(
            status_code=503,
            detail="LLM service is not configured. Set LLM_API_KEY in environment.",
        )


@router.post("/analyze", response_model=ThreatAnalysisResponse)
async def analyze_session(
    body: ThreatAnalysisRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ThreatAnalysisResponse:
    """Run AI-powered threat analysis on a specific honeypot session."""
    _require_llm()

    query = (
        select(SessionLog, AttackerProfile)
        .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
        .where(SessionLog.id == body.session_id)
    )
    row = (await db.execute(query)).first()
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")

    session, profile = row
    result = await app_state.llm_service.analyze_session(
        session=session,
        profile=profile,
        additional_context=body.context or "",
    )

    return ThreatAnalysisResponse(
        session_id=body.session_id,
        summary=result["summary"],
        risk_assessment=result["risk_assessment"],
        recommended_actions=result["recommended_actions"],
        ioc_indicators=result["ioc_indicators"],
        ttps=result["ttps"],
        confidence=result["confidence"],
        model_used=result["model_used"],
    )


@router.post("/chat", response_model=ChatResponse)
async def chat_threat_intel(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ChatResponse:
    """Conversational AI threat intelligence analyst."""
    _require_llm()

    session_context = None
    if body.session_id:
        query = (
            select(SessionLog, AttackerProfile)
            .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
            .where(SessionLog.id == body.session_id)
        )
        row = (await db.execute(query)).first()
        if row:
            session, profile = row
            cmds = [c.get("command", "") for c in (session.commands or [])[:30]]
            session_context = (
                f"Session {session.id} | IP: {session.attacker_ip} | "
                f"Honeypot: {session.honeypot} | Protocol: {session.protocol} | "
                f"Threat Level: {profile.threat_level} | Score: {profile.threat_score} | "
                f"VPN: {profile.vpn_detected} | Country: {profile.country} | "
                f"Commands: {'; '.join(cmds)}"
            )

    result = await app_state.llm_service.chat(
        message=body.message,
        conversation_history=body.conversation_history,
        session_context=session_context,
    )

    return ChatResponse(
        reply=result["reply"],
        model_used=result["model_used"],
        tokens_used=result["tokens_used"],
    )


@router.get("/status")
async def ai_status(current_user: User = Depends(get_current_user)) -> dict:
    """Check if AI/LLM service is available and configured."""
    configured = app_state.llm_service is not None
    return {
        "configured": configured,
        "model": app_state.llm_service.model if configured else None,
    }
