from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import cast, delete, select
from sqlalchemy.dialects.postgresql import INET as PG_INET
from sqlalchemy.ext.asyncio import AsyncSession

from config import CAIRO_TZ, get_settings
from models import AttackerProfile, SessionLog
from schemas import GatewayScoreRequest
from services.ip_reputation import (
    has_any_suspicious_username,
    is_deprecated_client,
    is_in_cidr_list,
    is_known_scanner,
    is_suspicious_username,
    match_any_pattern,
    SAFE_COMMAND_PATTERNS,
    SUSPICIOUS_COMMAND_PATTERNS,
)
from state import app_state

logger = logging.getLogger(__name__)


async def classify_connection(
    payload: GatewayScoreRequest,
    attempt: int = 1,
    db: Optional[AsyncSession] = None,
) -> dict:
    settings = get_settings()

    # ---- DB: check reconnect + store temporary session entry ----
    is_reconnect = False
    subnet_ip_count = 0
    session_id = None
    profile = None

    if db is not None:
        now_dt = datetime.now(CAIRO_TZ).replace(tzinfo=None)
        window_start = now_dt - timedelta(seconds=60)

        # Clean up stale gateway sessions (abandoned pass-1 sessions >5min old)
        await db.execute(
            delete(SessionLog).where(
                SessionLog.attacker_ip == cast(payload.src_ip, PG_INET),
                SessionLog.honeypot == "gateway",
                SessionLog.start_time < now_dt - timedelta(minutes=5),
            )
        )

        # R12: ANY recent session from this IP (gateway, cowrie, dionaea — all of them)
        result = await db.execute(
            select(SessionLog.id).where(
                SessionLog.attacker_ip == cast(payload.src_ip, PG_INET),
                SessionLog.start_time >= window_start,
            ).limit(1)
        )
        is_reconnect = result.scalar() is not None

        # Session reuse: only gateway sessions (re-call from the same connection)
        result = await db.execute(
            select(SessionLog).where(
                SessionLog.attacker_ip == cast(payload.src_ip, PG_INET),
                SessionLog.start_time >= window_start,
                SessionLog.honeypot == "gateway",
            ).order_by(SessionLog.start_time.desc()).limit(1)
        )
        recent_gateway = result.scalar_one_or_none()

        # Subnet scan: distinct IPs in same /24 within 60s
        subnet_ip_count = 0
        try:
            import ipaddress
            net = ipaddress.ip_network(payload.src_ip + "/24", strict=False)
            from sqlalchemy import text
            subnet_result = await db.execute(
                text(
                    "SELECT COUNT(DISTINCT attacker_ip) FROM session_logs "
                    "WHERE attacker_ip << :cidr AND start_time >= :since"
                ),
                {"cidr": str(net), "since": window_start},
            )
            subnet_ip_count = (await subnet_result.scalar()) or 0
        except Exception:
            pass

        # Get or create AttackerProfile
        result = await db.execute(
            select(AttackerProfile).where(AttackerProfile.ip == cast(payload.src_ip, PG_INET))
        )
        profile = result.scalar_one_or_none()
        if profile is None:
            profile = AttackerProfile(ip=payload.src_ip)
            db.add(profile)

        # Reuse session from first pass if this is a re-call
        if recent_gateway is not None and attempt >= 2:
            session_id = recent_gateway.id
            recent_gateway.raw_log = payload.model_dump()
        else:
            session = SessionLog(
                attacker_ip=payload.src_ip,
                honeypot="gateway",
                protocol="ssh",
                start_time=now_dt,
                commands=[],
                credentials_tried=[],
                malware_hashes=[],
                raw_log=payload.model_dump(),
            )
            session.attacker = profile
            db.add(session)
            await db.flush()
            session_id = session.id
    else:
        now_dt = datetime.now(CAIRO_TZ).replace(tzinfo=None)

    llm_used = False
    llm_explanation = ""
    user_type = "unknown"

    # ---- Pre-gate: known attacker? skip all tiers, route directly to honeypot ----
    if profile is not None and profile.threat_level >= 2 and profile.total_sessions >= 1:
        decision = "honeypot"
        confidence = 1.00
        arbitrate_reason = (
            f"known attacker — threat_level={profile.threat_level}, "
            f"sessions={profile.total_sessions}"
        )
        verdict = "decided"
        ml_level = -1
        ml_confidence = 0.0
    else:
        # ---- Tier 1: Heuristic rules → recommendation only ----
        rule_decision, rule_confidence, rule_reason = _run_heuristic_rules(
            payload, settings, is_reconnect
        )

        # ---- Extract rich signals from payload (feeds both ML and LLM) ----
        signals = _extract_signals(payload, is_reconnect)
        signals["is_known_scanner_ip"] = 1.0 if is_known_scanner(payload.src_ip) else 0.0
        signals["is_tor"] = 0.0
        signals["subnet_ip_count"] = float(subnet_ip_count)

        # ---- Tier 2: ML always runs (independent verification) ----
        ml_level, ml_confidence, ml_decision = _run_pre_session_ml(signals)

        # ---- Tier 3: Arbitrate — compare rule recommendation vs ML verdict ----
        decision, confidence, arbitrate_reason, verdict = _arbitrate(
            rule_decision, rule_confidence, rule_reason,
            ml_level, ml_confidence, ml_decision,
        )

        # ---- Tier 4: On first pass, return 'inconclusive' so gateway waits for more signals ----
        # On second pass (or if already decided), run LLM as final arbiter if still stuck.
        if verdict == "inconclusive":
            if attempt >= 2:
                llm_result = await _run_llm_tier(
                    payload, signals,
                    rule_decision, rule_confidence, rule_reason,
                    ml_level, ml_confidence, ml_decision,
                )
                if llm_result:
                    llm_used = True
                    decision = llm_result.get("decision", "honeypot")
                    confidence = llm_result.get("confidence", 0.60)
                    user_type = llm_result.get("user_type", "unknown")
                    llm_explanation = llm_result.get("explanation", "")
                    arbitrate_reason = f"LLM final verdict: {llm_explanation[:80]}"
                else:
                    decision = "honeypot"
                    confidence = 0.55
                    arbitrate_reason = "LLM unavailable — safe fallback to honeypot"
            # On attempt=1: leave decision as 'inconclusive' so gateway knows to wait

    # ---- Post-decision DB cleanup ----
    if db is not None and session_id is not None:
        if decision == "real":
            if profile is not None and profile.total_sessions == 0:
                await db.delete(profile)
            elif session_id is not None:
                await db.execute(
                    delete(SessionLog).where(SessionLog.id == session_id)
                )
        elif decision == "honeypot" and profile is not None:
            profile.last_seen = now_dt
            profile.total_sessions += 1
        # "inconclusive": leave as-is — gateway will retry or session will be cleaned up later

    if not user_type or user_type == "unknown":
        user_type = _infer_user_type(decision, arbitrate_reason)

    return {
        "decision": decision,
        "confidence": round(confidence, 2),
        "reason": arbitrate_reason,
        "user_type": user_type,
        "ml_level": ml_level,
        "ml_confidence": round(ml_confidence, 2),
        "llm_used": llm_used,
        "llm_explanation": llm_explanation,
    }


# ---------------------------------------------------------------------------
# Signal extraction (feeds ML + LLM with rich features)
# ---------------------------------------------------------------------------

def _extract_signals(payload: GatewayScoreRequest, is_reconnect: bool) -> dict:
    now = datetime.now(CAIRO_TZ).replace(tzinfo=None)
    unique_usernames = list({u.lower() for u in payload.usernames_tried})

    # Password analysis
    passwords = getattr(payload, "passwords_tried", []) or []
    entropy = _password_entropy(passwords)
    has_common = 1.0 if any(_is_common_password(p) for p in passwords) else 0.0
    repeating = 1.0 if len(passwords) >= 2 and len(set(passwords)) < len(passwords) else 0.0
    rotating = 1.0 if len(passwords) >= 2 and len(set(passwords)) == len(passwords) else 0.0

    return {
        "src_ip": payload.src_ip,
        "src_port": payload.src_port,
        "client_version": payload.client_version or "",
        "kex_algorithms_hash": payload.kex_algorithms_hash or "",
        # Numeric signals
        "auth_attempts_count": payload.auth_attempts_count,
        "time_to_first_auth": payload.time_to_first_auth,
        "auth_attempt_interval": payload.auth_attempt_interval,
        "unique_username_count": len(unique_usernames),
        "suspicious_username_count": sum(
            1 for u in unique_usernames if is_suspicious_username(u)
        ),
        # Boolean signals (1.0 / 0.0)
        "public_key_attempted": 1.0 if payload.public_key_attempted else 0.0,
        "shell_requested": 1.0 if payload.shell_requested else 0.0,
        "is_interactive": 1.0 if payload.is_interactive else 0.0,
        "has_exec_command": 1.0 if payload.exec_command else 0.0,
        "suspicious_exec": (
            1.0 if payload.exec_command and match_any_pattern(payload.exec_command, SUSPICIOUS_COMMAND_PATTERNS)
            else 0.0
        ),
        "safe_exec": (
            1.0 if payload.exec_command and match_any_pattern(payload.exec_command, SAFE_COMMAND_PATTERNS)
            else 0.0
        ),
        "is_deprecated_client": (
            1.0 if payload.client_version and is_deprecated_client(payload.client_version)
            else 0.0
        ),
        "is_rapid_reconnect": 1.0 if is_reconnect else 0.0,
        # Password analysis
        "avg_password_entropy": entropy,
        "has_common_password": has_common,
        "repeating_password": repeating,
        "rotating_passwords": rotating,
        # Temporal
        "hour_of_day": float(now.hour),
        "is_weekend": 1.0 if now.weekday() >= 5 else 0.0,
        # Method diversity
        "auth_method_count": len(payload.auth_methods_used),
    }


# ---------------------------------------------------------------------------
# Tier 1: Heuristic rules — first-match-wins recommendation engine
# ---------------------------------------------------------------------------

def _run_heuristic_rules(
    payload: GatewayScoreRequest,
    settings,
    is_reconnect: bool,
) -> tuple[str, float, str]:

    # ---- RULE 1: Whitelist CIDR ----
    if is_in_cidr_list(payload.src_ip, settings.GATEWAY_WHITELIST_CIDRS):
        return ("real", 1.00, "IP in whitelist CIDR")

    # ---- RULE 2: Pentester CIDR ----
    if is_in_cidr_list(payload.src_ip, getattr(settings, "PENTEST_CIDRS", "")):
        return ("honeypot", 0.95, "authorized pentester — routing to deception")

    # ---- RULE 3: Known Scanner IP Range ----
    if is_known_scanner(payload.src_ip):
        return ("honeypot", 0.98, "known internet scanner IP range")

    # ---- RULE 4: Deprecated/Attack SSH Client ----
    if payload.client_version and is_deprecated_client(payload.client_version):
        return ("honeypot", 0.95, f"deprecated SSH client: {payload.client_version}")

    # ---- RULE 5: Publickey + Clean Username ----
    if payload.public_key_attempted and not has_any_suspicious_username(
        payload.usernames_tried
    ):
        return ("real", 0.92, "publickey auth with clean username")

    # ---- RULE 6: Publickey + Suspicious Username + Bot Signal ----
    if payload.public_key_attempted:
        fast_interval = payload.auth_attempt_interval > 0 and payload.auth_attempt_interval < 0.5
        fast_connect = payload.time_to_first_auth > 0 and payload.time_to_first_auth < 0.15
        if fast_interval or fast_connect or is_reconnect:
            return ("honeypot", 0.88, "publickey + suspicious username + bot behavior")

    # ---- RULE 7: Credential Spray (≥4 attempts) ----
    if payload.auth_attempts_count >= 4:
        return ("honeypot", 0.97, f"credential spray: {payload.auth_attempts_count} attempts")

    # ---- RULE 8: Username Enumeration (≥3 different usernames) ----
    unique_usernames = [u.lower() for u in payload.usernames_tried]
    if len(set(unique_usernames)) >= 3:
        return ("honeypot", 0.92, f"username enumeration: {len(set(unique_usernames))} distinct usernames")

    # ---- RULE 9: Suspicious Username + Bot-like Behavior ----
    for u in payload.usernames_tried:
        if is_suspicious_username(u):
            fast_auth = payload.auth_attempt_interval > 0 and payload.auth_attempt_interval < 0.5
            multi_attempt = payload.auth_attempts_count >= 2
            if fast_auth or multi_attempt:
                return ("honeypot", 0.88, f"suspicious username with bot-like behavior: {u}")

    # ---- RULE 10: Bot Auth Speed (<0.3s between attempts) ----
    if (
        payload.auth_attempts_count >= 2
        and payload.auth_attempt_interval > 0
        and payload.auth_attempt_interval < 0.3
        and not _is_service_account(payload, settings)
    ):
        return (
            "honeypot",
            0.90,
            f"automated auth speed: {payload.auth_attempt_interval:.2f}s interval",
        )

    # ---- RULE 11: Bot Connect Speed (<0.15s to first auth) ----
    if (
        payload.time_to_first_auth > 0
        and payload.time_to_first_auth < 0.15
        and not _is_service_account(payload, settings)
    ):
        return (
            "honeypot",
            0.82,
            f"scanner connect speed: {payload.time_to_first_auth:.2f}s to first auth",
        )

    # ---- RULE 12: Rapid Reconnect (same IP within 60s) ----
    if is_reconnect:
        return ("honeypot", 0.88, "rapid reconnect from same IP within 60s")

    # ---- RULE 13: Multi-Method Auth ----
    if len(payload.auth_methods_used) >= 2 and payload.auth_attempts_count >= 3:
        return ("honeypot", 0.85, f"multiple auth methods attempted: {', '.join(payload.auth_methods_used)}")

    # ---- RULE 14: Suspicious Exec Command ----
    if payload.exec_command and match_any_pattern(payload.exec_command, SUSPICIOUS_COMMAND_PATTERNS):
        return ("honeypot", 0.95, f"suspicious command: {payload.exec_command[:60]}")

    # ---- RULE 15: Clean Non-Interactive Exec ----
    if payload.exec_command and not payload.is_interactive and match_any_pattern(payload.exec_command, SAFE_COMMAND_PATTERNS):
        return ("real", 0.72, f"clean non-interactive exec: {payload.exec_command[:40]}")

    # ---- RULE 16: Clean Interactive Shell (publickey) ----
    if (
        payload.shell_requested
        and payload.is_interactive
        and payload.public_key_attempted
        and not has_any_suspicious_username(payload.usernames_tried)
        and payload.time_to_first_auth > 0.5
    ):
        return ("real", 0.85, "clean interactive shell with key + human-paced auth")

    # ---- RULE 17: Clean Password Login (no spray, clean username, human timing) ----
    if (
        payload.auth_attempts_count <= 2
        and not payload.public_key_attempted
        and not has_any_suspicious_username(payload.usernames_tried)
        and payload.time_to_first_auth > 1.0
        and (payload.shell_requested or not payload.exec_command)
    ):
        return ("real", 0.72, "clean password login — human timing + clean username")

    # ---- RULE 18: No strong signal — undecided (let AI decide) ----
    return ("undecided", 0.50, "no strong signal — deferring to AI tiers")


# ---------------------------------------------------------------------------
# Tier 2: ML verification — VotingClassifier (LogisticRegression + GradientBoost)
# ---------------------------------------------------------------------------

PRE_SESSION_FEATURE_ORDER = [
    "auth_attempts_count",
    "unique_username_count",
    "suspicious_username_count",
    "time_to_first_auth",
    "auth_attempt_interval",
    "public_key_attempted",
    "shell_requested",
    "is_interactive",
    "has_exec_command",
    "suspicious_exec",
    "safe_exec",
    "is_deprecated_client",
    "is_rapid_reconnect",
    "auth_method_count",
    "hour_of_day",
    "is_weekend",
    "is_known_scanner_ip",
    "is_tor",
    "avg_password_entropy",
    "has_common_password",
    "repeating_password",
    "rotating_passwords",
    "subnet_ip_count",
]


def _run_pre_session_ml(signals: dict) -> tuple[int, float, str]:
    if app_state.pre_session_model is None:
        return (-1, 0.0, "")

    try:
        import numpy as np

        feature_vector = [
            float(signals.get(name, 0))
            for name in PRE_SESSION_FEATURE_ORDER
        ]

        model = app_state.pre_session_model
        proba = model.predict_proba(np.array([feature_vector], dtype=np.float64))[0]
        # proba[0] = honeypot, proba[1] = real
        confidence = float(max(proba))
        is_real = proba[1] >= 0.5
        decision = "real" if is_real else "honeypot"
        level = 0 if is_real else 4

        return (level, confidence, decision)
    except Exception as exc:
        logger.debug("Pre-session ML scoring failed: %s", exc)
        return (-1, 0.0, "")


# ---------------------------------------------------------------------------
# Tier 3: Arbitrate — compare rules vs ML, escalate disagreements to LLM
# ---------------------------------------------------------------------------

def _arbitrate(
    rule_decision: str,
    rule_confidence: float,
    rule_reason: str,
    ml_level: int,
    ml_confidence: float,
    ml_decision: str,
) -> tuple[str, float, str, str]:
    """Returns (decision, confidence, reason, verdict_type).

    verdict_type is 'decided' (route now) or 'inconclusive' (wait for more signals).
    """

    # ML unavailable → inconclusive, need more signals
    if ml_level < 0:
        return ("inconclusive", 0.50, "ML unavailable — need more signals", "inconclusive")

    # ---- Heuristic undecided → ML decides alone ----
    if rule_decision == "undecided":
        if ml_confidence >= 0.75:
            return (
                ml_decision,
                ml_confidence,
                f"ML decided {ml_decision} (level={ml_level}, conf={ml_confidence:.2f}) — heuristic undecided",
                "decided",
            )
        return (
            "inconclusive",
            ml_confidence,
            f"heuristic undecided, ML confidence too low ({ml_confidence:.2f} < 0.75)",
            "inconclusive",
        )

    # ---- Both agree → check confidence threshold ----
    if rule_decision == ml_decision:
        combined = min(1.0, max(rule_confidence, ml_confidence) + 0.05)
        if combined >= 0.75:
            return (
                rule_decision,
                combined,
                f"heuristic ({rule_confidence:.2f}) + ML ({ml_confidence:.2f}) agree → {rule_decision}",
                "decided",
            )
        return (
            "inconclusive",
            combined,
            f"both agree {rule_decision} but confidence too low ({combined:.2f} < 0.75)",
            "inconclusive",
        )

    # ---- ML strongly overrides weak heuristic (R6 false-positive bypass) ----
    if rule_decision == "honeypot" and ml_decision == "real" and ml_confidence >= 0.85:
        return (
            ml_decision,
            ml_confidence,
            f"ML overrides heuristic — {rule_reason} but ML sees real patterns (conf={ml_confidence:.2f})",
            "decided",
        )

    # ---- Rules strongly overrule ML (whitelist / high-confidence rules) ----
    if rule_decision == "real" and rule_confidence >= 0.95:
        return (
            rule_decision,
            rule_confidence,
            f"Rules overrule ML — high-confidence real ({rule_reason})",
            "decided",
        )

    # ---- Disagree → inconclusive, need more signals + LLM ----
    return (
        "inconclusive",
        min(rule_confidence, ml_confidence),
        f"disagreement: heuristic={rule_decision} ({rule_confidence:.2f}) vs ML={ml_decision} ({ml_confidence:.2f})",
        "inconclusive",
    )


# ---------------------------------------------------------------------------
# Tier 4: LLM tiebreaker
# ---------------------------------------------------------------------------

async def _run_llm_tier(
    payload: GatewayScoreRequest,
    signals: dict,
    rule_decision: str,
    rule_confidence: float,
    rule_reason: str,
    ml_level: int,
    ml_confidence: float,
    ml_decision: str,
) -> dict | None:
    if app_state.llm_service is None:
        return None

    for retry in range(2):
        try:
            signal_lines = [
                f"Source IP: {payload.src_ip}:{payload.src_port}",
                f"Client: {payload.client_version or 'unknown'} (deprecated: {bool(signals.get('is_deprecated_client'))})",
                f"KEX fingerprint: {payload.kex_algorithms_hash or 'unknown'}",
                f"Time to first auth: {payload.time_to_first_auth:.3f}s",
                f"Auth attempts: {payload.auth_attempts_count}",
                f"Auth interval: {payload.auth_attempt_interval:.3f}s",
                f"Auth methods: {', '.join(payload.auth_methods_used) or 'password'} (count: {signals.get('auth_method_count', 1)})",
                f"Usernames: {', '.join(payload.usernames_tried[:10]) if payload.usernames_tried else 'none'}",
                f"  Suspicious usernames: {int(signals.get('suspicious_username_count', 0))} of {signals.get('unique_username_count', 0)}",
                f"Publickey attempted: {payload.public_key_attempted}",
                f"Session type: {'interactive shell' if payload.shell_requested else 'exec: ' + (payload.exec_command or 'none')}",
                f"  Suspicious exec: {bool(signals.get('suspicious_exec'))} | Safe exec: {bool(signals.get('safe_exec'))}",
                f"Interactive: {payload.is_interactive}",
                f"Rapid reconnect: {bool(signals.get('is_rapid_reconnect'))}",
                f"Known scanner IP: {bool(signals.get('is_known_scanner_ip'))}",
                f"Tor exit node: {bool(signals.get('is_tor'))}",
                f"Subnet IPs in 60s: {int(signals.get('subnet_ip_count', 0))}",
                f"Password entropy: {signals.get('avg_password_entropy', 0):.2f} | Common: {bool(signals.get('has_common_password'))} | Repeating: {bool(signals.get('repeating_password'))} | Rotating: {bool(signals.get('rotating_passwords'))}",
                f"Hour: {int(signals.get('hour_of_day', 12))} (weekend: {bool(signals.get('is_weekend'))})",
                "",
                f"Heuristic recommendation: {rule_decision} (confidence: {rule_confidence:.2f})",
                f"Heuristic reason: {rule_reason}",
                f"ML verdict: {ml_decision} (level={ml_level}, confidence={ml_confidence:.2f})" if ml_level >= 0 else "ML: not available",
                "",
                "Heuristic and ML are inconclusive or disagree. You are the final arbiter.",
                "Classify this connection as 'real' or 'honeypot'. Return JSON only.",
            ]
            prompt = "\n".join(signal_lines)

            result = await app_state.llm_service.classify_connection(prompt)
            if result and result.get("decision") in ("real", "honeypot"):
                return result
            if retry < 1:
                import asyncio as _asyncio
                await _asyncio.sleep(1.5)
        except Exception as exc:
            logger.warning("LLM tier attempt %d failed: %s", retry + 1, exc)
            if retry < 1:
                import asyncio as _asyncio
                await _asyncio.sleep(1.5)

    return None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

async def _check_tor(ip: str) -> bool:
    try:
        if app_state.vpn_detector:
            result = await app_state.vpn_detector.check(ip)
            return bool(result.tor)
    except Exception:
        pass
    return False


def _infer_user_type(decision: str, reason: str) -> str:
    lower = reason.lower()

    # Rule-produced reasons — keyword matching works perfectly
    is_arbitrate = any(
        w in lower
        for w in (
            "agree", "disagreement", "override", "overrule",
            "ml decided", "llm", "inconclusive", "undecided", "defer",
        )
    )

    if not is_arbitrate:
        if "whitelist" in lower:
            return "normal_user"
        if "clean" in lower:
            return "normal_user"
        if "scanner" in lower:
            return "scanner"
        if "pentester" in lower:
            return "pentester"
        if "spray" in lower or "enumeration" in lower:
            return "credential_stuffer"
        if "bot" in lower or "automated" in lower:
            return "brute_force_bot"
        if "suspicious" in lower or "deprecated" in lower:
            return "advanced_attacker"
        if "reconnect" in lower or "multiple" in lower:
            return "advanced_attacker"

    # Arbitrate / LLM / fallback — use the final decision
    if decision == "real":
        return "normal_user"
    if decision == "honeypot":
        return "advanced_attacker"
    return "unknown"


def _is_service_account(payload: GatewayScoreRequest, settings) -> bool:
    patterns = getattr(settings, "SERVICE_ACCOUNT_USERNAME_PATTERNS", "")
    if not patterns:
        return False
    for u in payload.usernames_tried:
        for p in patterns.split(","):
            p = p.strip()
            if p and p.lower() in u.lower():
                return True
    return False


_COMMON_PASSWORDS = {
    "", "password", "123456", "12345678", "admin", "root", "1234", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "master", "123456789",
    "password1", "12345", "1234567890", "111111", "abc123", "pass",
    "test", "guest", "user", "ubuntu", "debian", "changeme", "default",
}


def _is_common_password(pw: str) -> bool:
    return pw.lower().strip() in _COMMON_PASSWORDS or len(pw) < 4


def _password_entropy(passwords: list[str]) -> float:
    if not passwords:
        return 0.0
    scores = []
    for pw in passwords:
        if not pw:
            scores.append(0.0)
        elif pw.lower().strip() in _COMMON_PASSWORDS:
            scores.append(0.05)
        else:
            has_upper = any(c.isupper() for c in pw)
            has_lower = any(c.islower() for c in pw)
            has_digit = any(c.isdigit() for c in pw)
            has_special = any(not c.isalnum() for c in pw)
            variety = sum([has_upper, has_lower, has_digit, has_special])
            length_bonus = min(len(pw) / 12.0, 1.0)
            score = (variety / 4.0) * 0.7 + length_bonus * 0.3
            if pw.isdigit():
                score *= 0.3
            scores.append(score)
    return round(sum(scores) / len(scores), 3)
