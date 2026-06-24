"""Shared canary-token trigger logic.

Used by both the public HMAC webhook (``routers/canary.py``) and the
honeypot-side detection hook in ``services/ingest.py``. Keeping the trigger
logic in one place means a canary fired from the tripwire HTTP server, from a
Cowrie shell command, or from a Dionaea FTP transfer all update the database,
attacker profile, and SOC dashboard the same way.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, cairo_iso, get_settings
from models import Alert, AttackerProfile, CanaryToken, SessionLog
from state import AppState, app_state

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Difficulty → default additive threat score
# ---------------------------------------------------------------------------
_DIFFICULTY_SCORE = {0: 0.05, 1: 0.15, 2: 0.25, 3: 0.40, 4: 0.60}


def default_score_value(difficulty: int) -> float:
    return _DIFFICULTY_SCORE.get(difficulty, 0.15)


# ---------------------------------------------------------------------------
# Honeypot-side bait → token mapping
#
# Each entry maps a case-insensitive substring (looked for in a Cowrie command
# or a Dionaea FTP/HTTP request) to the canary token it should fire. The token
# difficulties are seeded in ``backend/bootstrap.py``. Order matters: the first
# matching pattern wins, so more specific paths come first.
#
# NOTE: the level-0 (benign web bug) and level-3 (.env in leaked /.git) baits
# are served by the tripwire HTTP server and fire through the HMAC webhook +
# ``TRIPWIRE_TOKEN_MAP`` instead — they are intentionally NOT in this map.
# ---------------------------------------------------------------------------
_DEFAULT_BAIT_PATTERNS: list[tuple[str, str]] = [
    ("database_backup.sql", "e8ca06a6-7123-4a08-9262-38c347248e51"),  # Cowrie /tmp staging dump
    ("prod_db_dump.sql", "a1b2c3d4-e5f6-4071-8293-a4b5c6d7e8f9"),  # Cowrie /var/backups/db
    (".aws/credentials", "c3f1a2b4-5d6e-4f80-9a1b-2c3d4e5f6071"),  # Cowrie /home/deploy/.aws
    ("opt/app/.env", "d4e2b3c5-6e7f-4a91-8b2c-3d4e5f607182"),  # Cowrie /opt/app/.env
    ("id_rsa", "7aedcaf0-b627-4f6f-95e8-5e59d891147e"),  # Cowrie /root/.ssh
    (".bash_history", "b7c8d9e0-1f23-4a56-8b9c-0d1e2f3a4b5c"),  # Cowrie /root/.bash_history breadcrumb
    ("aws_credentials", "083ee719-79d9-4174-b471-076ecc4248d7"),  # L2 Dionaea FTP
    ("passwords.txt", "19eee70f-aefd-4afb-ab06-3598d374876b"),  # L1 Dionaea HTTP
]


def _load_bait_patterns() -> list[tuple[str, str]]:
    raw = getattr(get_settings(), "CANARY_BAIT_MAP", "") or ""
    if not raw.strip():
        return list(_DEFAULT_BAIT_PATTERNS)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("CANARY_BAIT_MAP is not valid JSON; using built-in patterns")
        return list(_DEFAULT_BAIT_PATTERNS)
    return [(str(k).lower(), str(v)) for k, v in data.items()]


def match_bait_token(text: str | None, honeypot: str | None = None) -> str | None:
    """Return the canary token id for the first bait pattern found in ``text``.

    ``text`` is typically the attacker's command (Cowrie ``input``) or the
    parsed Dionaea request line. Matching is case-insensitive substring.
    """
    if not text:
        return None
    haystack = text.lower()
    for pattern, token_id in _load_bait_patterns():
        if pattern in haystack:
            return token_id
    return None


# ---------------------------------------------------------------------------
# Lightweight cooldown so repeated reads of the same bait by the same IP do not
# spam identical alerts. Single-threaded asyncio → a plain dict is sufficient.
# ---------------------------------------------------------------------------
_last_fired: dict[str, float] = {}


def _cooldown_active(key: str, seconds: int) -> bool:
    if seconds <= 0 or not key:
        return False
    now = time.monotonic()
    last = _last_fired.get(key)
    if last is not None and (now - last) < seconds:
        return True
    _last_fired[key] = now
    if len(_last_fired) > 10_000:
        _last_fired.clear()
        _last_fired[key] = now
    return False


def _naive_cairo_now() -> datetime:
    return datetime.now(CAIRO_TZ).replace(tzinfo=None)


def _to_naive(ts: datetime | None) -> datetime:
    if ts is None:
        return _naive_cairo_now()
    if ts.tzinfo is not None:
        return ts.astimezone(CAIRO_TZ).replace(tzinfo=None)
    return ts


async def trigger_canary(
    db: AsyncSession,
    token_id: str,
    src_ip: str,
    *,
    timestamp: datetime | None = None,
    session: SessionLog | None = None,
    profile: AttackerProfile | None = None,
    source: str = "canary",
    user_agent: str = "",
    raw_log: dict[str, Any] | None = None,
    runtime_state: AppState = app_state,
    cooldown_key: str | None = None,
    cooldown_seconds: int = 0,
) -> Alert | None:
    """Register a canary trigger and emit an alert.

    Does NOT commit — the caller's transaction owns the commit. Returns the
    created :class:`Alert`, or ``None`` if the trigger was suppressed by the
    cooldown.

    When ``session`` is provided (honeypot-side detection) the alert is attached
    to that existing session and threat scoring is left to the caller. When it
    is ``None`` (public webhook) a dedicated ``honeypot='canary'`` session is
    created and scored here, preserving the original webhook behaviour.
    """
    if _cooldown_active(cooldown_key or "", cooldown_seconds):
        return None

    now = _naive_cairo_now()
    ts = _to_naive(timestamp)
    src_ip = str(src_ip)

    # Update trigger stats on the registered token if it exists.
    registered_token: CanaryToken | None = None
    try:
        token_uuid = uuid.UUID(str(token_id))
        registered_token = await db.get(CanaryToken, token_uuid)
    except (ValueError, AttributeError):
        registered_token = None
    if registered_token is not None:
        registered_token.trigger_count = (registered_token.trigger_count or 0) + 1
        registered_token.last_triggered_at = now

    diff = registered_token.difficulty if registered_token is not None else 3
    token_score_val = (
        registered_token.score_value
        if registered_token is not None and registered_token.score_value > 0
        else default_score_value(diff)
    )

    profile_created = False
    if profile is None:
        profile = await db.get(AttackerProfile, src_ip)
    if profile is None:
        profile = AttackerProfile(
            ip=src_ip,
            first_seen=now,
            last_seen=now,
            total_sessions=1,
        )
        db.add(profile)
        profile_created = True
    else:
        profile.last_seen = now

    profile.canary_triggered = True
    profile.canary_max_difficulty = max(profile.canary_max_difficulty or 0, diff)
    profile.canary_trigger_count = (profile.canary_trigger_count or 0) + 1
    profile.cumulative_canary_score = min(1.0, (profile.cumulative_canary_score or 0.0) + token_score_val)

    scorer_level = 0
    scorer_score = 0.0
    if session is None:
        if not profile_created:
            profile.total_sessions = (profile.total_sessions or 0) + 1
        session = SessionLog(
            id=uuid.uuid4(),
            attacker_ip=src_ip,
            honeypot="canary",
            protocol="http",
            start_time=ts,
            end_time=ts,
            commands=[],
            credentials_tried=[],
            malware_hashes=[],
            raw_log=raw_log or {"source": source, "token_id": str(token_id)},
        )
        db.add(session)
        await db.flush()

        if runtime_state.threat_scorer:
            scorer_score, scorer_level = await runtime_state.threat_scorer.score(
                session, profile, multi_protocol=False, known_bad_ip=bool(profile.vpn_detected)
            )

    additive_score = min(1.0, (profile.threat_score or 0.0) + token_score_val)
    profile.threat_score = max(scorer_score, additive_score)
    profile.threat_level = max(scorer_level, diff, profile.threat_level or 0)

    alert_level = max(diff, scorer_level)
    alert = Alert(
        session_id=session.id,
        attacker_ip=src_ip,
        threat_level=alert_level,
        message=f"Canary token triggered via {source}: {token_id} (difficulty={diff})",
    )
    db.add(alert)
    await db.flush()

    alert_data = {
        "id": str(alert.id),
        "session_id": str(session.id),
        "attacker_ip": src_ip,
        "threat_level": alert.threat_level,
        "message": alert.message,
        "created_at": cairo_iso(alert.created_at) if alert.created_at else cairo_iso(datetime.now(CAIRO_TZ)),
        "acknowledged": False,
    }

    if runtime_state.alert_manager:
        await runtime_state.alert_manager.broadcast(alert_data)

    if runtime_state.splunk_forwarder:
        await runtime_state.splunk_forwarder.send_event(
            {**alert_data, "raw_log": raw_log or {"source": source}},
            source=f"eviltwin-canary-{source}",
        )

    return alert
