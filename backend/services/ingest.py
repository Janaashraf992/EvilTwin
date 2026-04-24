from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from models import Alert, AttackerProfile, SessionLog
from schemas import LogIngestRequest, LogIngestResponse
from state import AppState, app_state


def session_uuid(src_ip: str, session: str) -> uuid.UUID:
    return uuid.uuid5(uuid.NAMESPACE_URL, f"{src_ip}:{session}")


def parse_honeypot(eventid: str) -> str:
    if eventid.startswith("cowrie"):
        return "cowrie"
    if eventid.startswith("dionaea"):
        return "dionaea"
    return "unknown"


async def ingest_event(
    payload: LogIngestRequest,
    db: AsyncSession,
    runtime_state: AppState = app_state,
) -> LogIngestResponse:
    started = time.perf_counter()
    src_ip = str(payload.src_ip)
    current_session_id = session_uuid(src_ip, payload.session)

    profile = await db.get(AttackerProfile, src_ip)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if profile is None:
        profile = AttackerProfile(
            ip=src_ip,
            first_seen=now,
            last_seen=now,
            total_sessions=1,
        )
        db.add(profile)
    else:
        profile.last_seen = now

    session = await db.get(SessionLog, current_session_id)
    if session is None:
        session = SessionLog(
            id=current_session_id,
            attacker_ip=src_ip,
            honeypot=parse_honeypot(payload.eventid),
            protocol=payload.protocol,
            start_time=payload.timestamp.replace(tzinfo=None),
            raw_log={"events": []},
            commands=[],
            credentials_tried=[],
            malware_hashes=[],
        )
        db.add(session)
    session.end_time = payload.timestamp.replace(tzinfo=None)

    if payload.input:
        session.commands = list(session.commands or [])
        session.commands.append(
            {
                "timestamp": payload.timestamp.isoformat(),
                "command": payload.input,
                "output": payload.message,
            }
        )

    if payload.username is not None or payload.password is not None:
        session.credentials_tried = list(session.credentials_tried or [])
        session.credentials_tried.append(
            {
                "username": payload.username or "",
                "password": payload.password or "",
                "success": payload.eventid.endswith("login.success"),
            }
        )

    existing_events = list((session.raw_log or {}).get("events", []))
    existing_events.append(payload.model_dump(mode="json"))
    session.raw_log = {"events": existing_events}

    if runtime_state.vpn_detector:
        vpn = await runtime_state.vpn_detector.check(src_ip)
        profile.vpn_detected = vpn.vpn or vpn.proxy or vpn.tor
        profile.country = vpn.country or profile.country
        profile.city = vpn.city or profile.city
        profile.isp = vpn.isp or profile.isp
        if vpn.latitude is not None:
            profile.latitude = vpn.latitude
        if vpn.longitude is not None:
            profile.longitude = vpn.longitude

    if runtime_state.threat_scorer:
        score, level = await runtime_state.threat_scorer.score(session, profile)
    else:
        score, level = 0.0, 0

    profile.threat_score = score
    profile.threat_level = level

    if level >= 3:
        alert = Alert(
            session_id=session.id,
            attacker_ip=src_ip,
            threat_level=level,
            message=f"High-risk session detected from {src_ip}",
        )
        db.add(alert)
        await db.flush()

        alert_data = {
            "id": str(alert.id),
            "session_id": str(session.id),
            "attacker_ip": src_ip,
            "threat_level": level,
            "message": alert.message,
            "created_at": alert.created_at.isoformat() if alert.created_at else now.isoformat(),
            "acknowledged": False,
        }

        if runtime_state.alert_manager:
            await runtime_state.alert_manager.broadcast(alert_data)

        if runtime_state.splunk_forwarder:
            await runtime_state.splunk_forwarder.send_event(
                {**alert_data, "raw_log": payload.model_dump(mode="json")},
                source="eviltwin-ingest",
            )

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if elapsed_ms > 2000:
        raise HTTPException(status_code=500, detail="Ingestion too slow")

    return LogIngestResponse(session_id=session.id, threat_score=score, threat_level=level)