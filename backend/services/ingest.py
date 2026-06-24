from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime

from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import INET as PG_INET
from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, cairo_iso, get_settings
from models import Alert, AttackerProfile, SessionLog
from schemas import LogIngestRequest, LogIngestResponse
from services.canary import match_bait_token, trigger_canary
from services.ip_correlation import resolve_for_connect, resolve_for_session
from state import AppState, app_state

logger = logging.getLogger(__name__)


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

    # Un-mask SSH-gateway-proxied sessions: the gateway re-originates the
    # attacker's connection to Cowrie, so payload.src_ip is the gateway. The
    # connect event carries the gateway's outbound port (src_port); use it to
    # recover the real client IP and remember it for the rest of the session.
    if payload.eventid.endswith("session.connect") and payload.src_port:
        real_ip = resolve_for_connect(payload.src_port, payload.session)
    else:
        real_ip = resolve_for_session(payload.session)
    if real_ip:
        src_ip = real_ip

    current_session_id = session_uuid(src_ip, payload.session)

    result = await db.execute(
        select(AttackerProfile).where(AttackerProfile.ip == cast(src_ip, PG_INET))
    )
    profile = result.scalar_one_or_none()
    now = datetime.now(CAIRO_TZ).replace(tzinfo=None)
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
        profile.total_sessions = (profile.total_sessions or 0) + 1

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

    # Honeypot-side canary detection: if the attacker touched a planted bait
    # file (Cowrie command or Dionaea FTP/HTTP request) fire the mapped token.
    detect_text = " ".join(part for part in (payload.input, payload.message) if part)
    bait_token = match_bait_token(detect_text, session.honeypot)
    if bait_token:
        await trigger_canary(
            db,
            bait_token,
            src_ip,
            timestamp=payload.timestamp,
            session=session,
            profile=profile,
            source=session.honeypot,
            runtime_state=runtime_state,
            cooldown_key=f"{src_ip}:{bait_token}",
            cooldown_seconds=get_settings().CANARY_INGEST_COOLDOWN_SECONDS,
        )

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

    known_bad_ip = bool(profile.vpn_detected)

    multi_protocol = False
    if profile.total_sessions and profile.total_sessions > 1:
        stmt = select(func.count(func.distinct(SessionLog.protocol))).where(SessionLog.attacker_ip == cast(src_ip, PG_INET))
        res = await db.execute(stmt)
        distinct_protocols = res.scalar() or 1
        multi_protocol = distinct_protocols > 1

    if runtime_state.threat_scorer:
        score, level = await runtime_state.threat_scorer.score(
            session, profile, multi_protocol=multi_protocol, known_bad_ip=known_bad_ip
        )
    else:
        score, level = 0.0, 0

    profile.threat_score = max(score, profile.threat_score or 0.0)
    profile.threat_level = max(level, profile.threat_level or 0)

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
            "created_at": cairo_iso(alert.created_at) if alert.created_at else cairo_iso(now),
            "acknowledged": False,
        }

        if runtime_state.alert_manager:
            await runtime_state.alert_manager.broadcast(alert_data)

    # Forward every event to Splunk regardless of threat level
    if runtime_state.splunk_forwarder:
        logger.debug("Forwarding to Splunk: %s", src_ip)
        event_data = {
            "session_id": str(session.id),
            "attacker_ip": src_ip,
            "honeypot": session.honeypot,
            "protocol": session.protocol,
            "threat_score": score,
            "threat_level": level,
            "event": payload.model_dump(mode="json"),
        }
        await runtime_state.splunk_forwarder.send_event(
            event_data,
            source=f"eviltwin-{session.honeypot}",
        )
    else:
        logger.debug("Splunk forwarder not available – skipping forward for %s", src_ip)

    elapsed_ms = (time.perf_counter() - started) * 1000.0
    if elapsed_ms > 2000:
        logger.warning("Ingestion slow: %.0fms for %s", elapsed_ms, src_ip)

    return LogIngestResponse(session_id=session.id, threat_score=score, threat_level=level)