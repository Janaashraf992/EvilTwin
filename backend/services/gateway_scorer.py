from __future__ import annotations

import logging
from datetime import datetime

from config import CAIRO_TZ, get_settings
from schemas import GatewayScoreRequest
from services.ip_reputation import (
    ConnectionHistory,
    get_connection_history,
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
) -> dict:
    settings = get_settings()
    conn_history = get_connection_history()
    conn_history.record_connect(payload.src_ip)

    is_tor = await _check_tor(payload.src_ip)

    decision, confidence, reason = _run_heuristic_rules(
        payload, settings, conn_history, is_tor
    )
    user_type = _infer_user_type(decision, reason)

    ml_level = -1
    ml_confidence = 0.0
    llm_used = False
    llm_explanation = ""

    if confidence < 0.85:
        ml_level, ml_confidence = _run_ml_tier(payload)
        decision, confidence = _blend_tiers(
            decision, confidence, ml_level, ml_confidence
        )

        if _needs_llm(decision, confidence, ml_level, ml_confidence, reason):
            llm_used = True
            llm_result = await _run_llm_tier(
                payload, decision, confidence, reason, ml_level
            )
            if llm_result:
                decision = llm_result.get("decision", decision)
                confidence = llm_result.get("confidence", confidence)
                user_type = llm_result.get("user_type", user_type)
                llm_explanation = llm_result.get("explanation", "")

    return {
        "decision": decision,
        "confidence": round(confidence, 2),
        "reason": reason,
        "user_type": user_type,
        "ml_level": ml_level,
        "ml_confidence": round(ml_confidence, 2),
        "llm_used": llm_used,
        "llm_explanation": llm_explanation,
    }


def _run_heuristic_rules(
    payload: GatewayScoreRequest,
    settings,
    conn_history: ConnectionHistory,
    is_tor: bool,
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

    # ---- RULE 4: Tor Exit Node ----
    if is_tor:
        return ("honeypot", 0.95, "Tor exit node — SSH from Tor is near-zero legitimate")

    # ---- RULE 5: Deprecated/Attack SSH Client ----
    if payload.client_version and is_deprecated_client(payload.client_version):
        return ("honeypot", 0.95, f"deprecated SSH client: {payload.client_version}")

    # ---- RULE 6: Publickey + Clean Username ----
    if payload.public_key_attempted and not has_any_suspicious_username(
        payload.usernames_tried
    ):
        return ("real", 0.92, "publickey auth with clean username")

    # ---- RULE 7: Publickey + Suspicious Username ----
    if payload.public_key_attempted:
        return ("honeypot", 0.88, "publickey auth but suspicious username")

    # ---- RULE 8: Credential Spray (≥4 attempts) ----
    if payload.auth_attempts_count >= 4:
        return ("honeypot", 0.97, f"credential spray: {payload.auth_attempts_count} attempts")

    # ---- RULE 9: Username Enumeration (≥3 different usernames) ----
    unique_usernames = [u.lower() for u in payload.usernames_tried]
    if len(set(unique_usernames)) >= 3:
        return ("honeypot", 0.92, f"username enumeration: {len(set(unique_usernames))} distinct usernames")

    # ---- RULE 10: Suspicious Username ----
    for u in payload.usernames_tried:
        if is_suspicious_username(u):
            return ("honeypot", 0.90, f"suspicious username: {u}")

    # ---- RULE 11: Bot Auth Speed (<0.3s between attempts) ----
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

    # ---- RULE 12: Bot Connect Speed (<0.15s to first auth) ----
    if payload.time_to_first_auth > 0 and payload.time_to_first_auth < 0.15 and not _is_service_account(payload, settings):
        return (
            "honeypot",
            0.82,
            f"scanner connect speed: {payload.time_to_first_auth:.2f}s to first auth",
        )

    # ---- RULE 13: Rapid Reconnect (same IP within 60s) ----
    if conn_history.was_recent_reconnect(payload.src_ip, window=60.0):
        return ("honeypot", 0.88, "rapid reconnect from same IP within 60s")

    # ---- RULE 14: Multi-Method Auth (only if multiple methods FAILED) ----
    if len(payload.auth_methods_used) >= 2 and payload.auth_attempts_count >= 3:
        return ("honeypot", 0.85, f"multiple auth methods attempted: {', '.join(payload.auth_methods_used)}")

    # ---- RULE 15: Suspicious Exec Command ----
    if payload.exec_command:
        if match_any_pattern(payload.exec_command, SUSPICIOUS_COMMAND_PATTERNS):
            return ("honeypot", 0.95, f"suspicious command: {payload.exec_command[:60]}")

    # ---- RULE 16: Clean Non-Interactive Exec ----
    if payload.exec_command and not payload.is_interactive:
        if match_any_pattern(payload.exec_command, SAFE_COMMAND_PATTERNS):
            return ("real", 0.72, f"clean non-interactive exec: {payload.exec_command[:40]}")

    # ---- RULE 17: Clean Interactive Shell ----
    if (
        payload.shell_requested
        and payload.is_interactive
        and payload.public_key_attempted
        and not has_any_suspicious_username(payload.usernames_tried)
        and payload.time_to_first_auth > 0.5
    ):
        return ("real", 0.82, "clean interactive shell with key + human-paced auth")

    # ---- RULE 18: Default Fallback ----
    return ("honeypot", 0.60, "no strong signal — safe fallback to honeypot")


def _run_ml_tier(payload: GatewayScoreRequest) -> tuple[int, float]:
    if app_state.threat_scorer is None or app_state.threat_scorer.pipeline is None:
        return (-1, 0.0)

    try:
        import numpy as np

        now = datetime.now(CAIRO_TZ)
        cred_spray = 1.0 if payload.auth_attempts_count >= 4 else 0.0
        session_duration_s = max(payload.time_to_first_auth or 5.0, 5.0)
        hour_of_day = float(now.hour)
        is_weekend = 1.0 if now.weekday() >= 5 else 0.0

        feature_vector = [
            0.0,
            0.0,
            0.0,
            0.0,
            cred_spray,
            session_duration_s,
            0.0,
            hour_of_day,
            is_weekend,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
            0.0,
        ]

        pipeline = app_state.threat_scorer.pipeline
        probabilities = pipeline.predict_proba(np.array([feature_vector]))[0]
        level = int(pipeline.predict(np.array([feature_vector]))[0])
        confidence = float(max(probabilities))

        return (level, confidence)
    except Exception as exc:
        logger.debug("ML pre-session scoring failed: %s", exc)
        return (-1, 0.0)


def _blend_tiers(
    heuristic_decision: str,
    heuristic_confidence: float,
    ml_level: int,
    ml_confidence: float,
) -> tuple[str, float]:
    if ml_level < 0:
        return (heuristic_decision, heuristic_confidence)

    ml_decision = "honeypot" if ml_level >= 2 else "real"

    if ml_decision == heuristic_decision:
        conf = min(1.0, max(heuristic_confidence, ml_confidence) + 0.04)
        return (heuristic_decision, conf)

    if ml_level >= 3 and ml_confidence > 0.80:
        return ("honeypot", ml_confidence)

    if heuristic_confidence < 0.85:
        conf = max(0.45, heuristic_confidence - 0.08)
        return (heuristic_decision, conf)

    return (heuristic_decision, heuristic_confidence)


def _needs_llm(
    decision: str,
    confidence: float,
    ml_level: int,
    ml_confidence: float,
    reason: str,
) -> bool:
    if app_state.llm_service is None:
        return False
    if confidence > 0.80:
        return False
    if ml_level >= 3 and ml_confidence > 0.80:
        return True
    if confidence < 0.75:
        return True
    if "default" in reason.lower() or "fallback" in reason.lower():
        return True
    return False


async def _run_llm_tier(
    payload: GatewayScoreRequest,
    heuristic_decision: str,
    heuristic_confidence: float,
    reason: str,
    ml_level: int,
) -> dict | None:
    if app_state.llm_service is None:
        return None

    try:
        signal_lines = [
            f"Source IP: {payload.src_ip}:{payload.src_port}",
            f"Client: {payload.client_version or 'unknown'}",
            f"KEX fingerprint: {payload.kex_algorithms_hash or 'unknown'}",
            f"Time to first auth: {payload.time_to_first_auth:.3f}s",
            f"Auth attempts: {payload.auth_attempts_count}",
            f"Auth interval: {payload.auth_attempt_interval:.3f}s",
            f"Auth methods: {', '.join(payload.auth_methods_used) or 'password'}",
            f"Usernames: {', '.join(payload.usernames_tried[:10]) if payload.usernames_tried else 'none'}",
            f"Publickey attempted: {payload.public_key_attempted}",
            f"Session type: {'interactive shell' if payload.shell_requested else 'exec: ' + (payload.exec_command or 'none')}",
            f"Interactive: {payload.is_interactive}",
            f"",
            f"Heuristic result: {heuristic_decision} (confidence: {heuristic_confidence:.2f})",
            f"Heuristic reason: {reason}",
            f"ML result: {'level ' + str(ml_level) if ml_level >= 0 else 'not run'}",
            f"",
            f"Classify this connection. Return JSON only.",
        ]
        prompt = "\n".join(signal_lines)

        result = await app_state.llm_service.classify_connection(prompt)
        return result
    except Exception as exc:
        logger.warning("LLM gateway classification failed: %s", exc)

    return None


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
    if "whitelist" in lower:
        return "normal_user"
    if "clean" in lower or "normal" in lower:
        return "normal_user"
    if "scanner" in lower or "connect speed" in lower:
        return "scanner"
    if "pentester" in lower:
        return "pentester"
    if "spray" in lower or "enumeration" in lower or "brute" in lower:
        return "credential_stuffer"
    if "bot" in lower or "automated" in lower:
        return "brute_force_bot"
    if "suspicious" in lower or "deprecated" in lower:
        return "advanced_attacker"
    if "default" in lower or "fallback" in lower or "no strong signal" in lower:
        return "unknown"
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
