from __future__ import annotations

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, REAL_HONEYPOT_TYPES, cairo_iso

from database import get_db
from deps import get_current_user
from models import Alert, AttackerProfile, SessionLog, User
from schemas import StatsResponse

router = APIRouter(prefix="/stats", tags=["dashboard"])


@router.get("", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> StatsResponse:
    since = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(hours=24)

    total_sessions_24h = (
        await db.execute(
            select(func.count(SessionLog.id)).where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
        )
    ).scalar_one()

    unique_attackers_24h = (
        await db.execute(
            select(func.count(func.distinct(SessionLog.attacker_ip))).where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
        )
    ).scalar_one()

    critical_alerts_24h = (
        await db.execute(
            select(func.count(Alert.id)).where(Alert.created_at >= since, Alert.threat_level >= 3)
        )
    ).scalar_one()

    canary_triggers_24h = (
        await db.execute(
            select(func.count(SessionLog.id)).where(
                SessionLog.start_time >= since, SessionLog.honeypot == "canary"
            )
        )
    ).scalar_one()

    vpn_users_count = (
        await db.execute(
            select(func.count(func.distinct(SessionLog.attacker_ip))).where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
                SessionLog.attacker_ip.in_(
                    select(AttackerProfile.ip).where(AttackerProfile.vpn_detected == True)
                ),
            )
        )
    ).scalar_one()

    honeypot_rows = (
        await db.execute(
            select(SessionLog.honeypot, func.count(SessionLog.id).label("count"))
            .where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
            .group_by(SessionLog.honeypot)
        )
    ).all()
    honeypot_breakdown = [{"honeypot": row.honeypot, "count": row.count} for row in honeypot_rows]

    sessions = (
        await db.execute(
            select(SessionLog)
            .where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
            .order_by(SessionLog.start_time.desc())
        )
    ).scalars().all()

    top_counter: dict[str, int] = {}
    attacks_by_hour: dict[int, int] = {h: 0 for h in range(24)}
    for session in sessions:
        attacks_by_hour[session.start_time.hour] += 1
        for cmd in session.commands or []:
            command = str(cmd.get("command", "")).strip()
            if not command:
                continue
            top_counter[command] = top_counter.get(command, 0) + 1

    top_commands = [
        {"command": cmd, "count": count}
        for cmd, count in sorted(top_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    ]

    attacks_by_hour_list = [{"hour": hour, "count": count} for hour, count in sorted(attacks_by_hour.items())]

    level_rows = (
        await db.execute(
            select(Alert.threat_level, func.count(Alert.id))
            .where(Alert.created_at >= since)
            .group_by(Alert.threat_level)
        )
    ).all()
    threat_level_distribution = [{"level": int(level), "count": count} for level, count in level_rows]

    return StatsResponse(
        total_sessions_24h=total_sessions_24h,
        unique_attackers_24h=unique_attackers_24h,
        critical_alerts_24h=critical_alerts_24h,
        canary_triggers_24h=canary_triggers_24h,
        vpn_users_count=vpn_users_count,
        honeypot_breakdown=honeypot_breakdown,
        top_commands=top_commands,
        attacks_by_hour=attacks_by_hour_list,
        threat_level_distribution=threat_level_distribution,
    )


@router.get("/timeline")
async def get_timeline(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return attack counts per hour for the last 24 hours."""
    since = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(hours=24)
    sessions = (
        await db.execute(
            select(SessionLog.start_time)
            .where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
        )
    ).scalars().all()

    by_hour: dict[int, int] = {h: 0 for h in range(24)}
    for start_time in sessions:
        by_hour[start_time.hour] += 1

    return [{"hour": h, "count": c} for h, c in sorted(by_hour.items())]


@router.get("/top-attackers")
async def get_top_attackers(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[dict]:
    """Return top 10 attackers by session count in the last 24 hours."""
    since = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(hours=24)

    rows = (
        await db.execute(
            select(
                SessionLog.attacker_ip,
                func.count(SessionLog.id).label("session_count"),
                func.max(AttackerProfile.threat_level).label("max_threat"),
                func.max(AttackerProfile.country).label("country"),
            )
            .join(AttackerProfile, AttackerProfile.ip == SessionLog.attacker_ip)
            .where(
                SessionLog.start_time >= since,
                SessionLog.honeypot.in_(REAL_HONEYPOT_TYPES),
            )
            .group_by(SessionLog.attacker_ip)
            .order_by(func.count(SessionLog.id).desc())
            .limit(10)
        )
    ).all()

    return [
        {
            "ip": str(row.attacker_ip),
            "session_count": row.session_count,
            "threat_level": row.max_threat or 0,
            "country": row.country or "",
        }
        for row in rows
    ]


@router.get("/vpn-users")
async def get_vpn_users(
    db: AsyncSession = Depends(get_db),
    _current_user: User = Depends(get_current_user),
) -> list[dict]:
    since = datetime.now(CAIRO_TZ).replace(tzinfo=None) - timedelta(hours=24)

    rows = (
        await db.execute(
            select(
                AttackerProfile.ip,
                AttackerProfile.country,
                AttackerProfile.city,
                AttackerProfile.isp,
                AttackerProfile.threat_level,
                func.count(SessionLog.id).label("session_count"),
                func.max(SessionLog.start_time).label("last_seen"),
            )
            .join(SessionLog, SessionLog.attacker_ip == AttackerProfile.ip)
            .where(
                AttackerProfile.vpn_detected == True,
                SessionLog.start_time >= since,
            )
            .group_by(AttackerProfile.ip)
            .order_by(func.count(SessionLog.id).desc())
            .limit(100)
        )
    ).all()

    return [
        {
            "ip": str(row.ip),
            "city": row.city or "",
            "country": row.country or "",
            "isp": row.isp or "",
            "session_count": row.session_count,
            "threat_level": row.threat_level or 0,
            "last_seen": cairo_iso(row.last_seen) if row.last_seen else None,
        }
        for row in rows
    ]
