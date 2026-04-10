from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

FEATURES = [
    "cmd_count",
    "unique_cmd_ratio",
    "download_attempt",
    "priv_escalation_attempt",
    "credential_spray",
    "session_duration_s",
    "commands_per_minute",
    "hour_of_day",
    "is_weekend",
    "vpn_detected",
    "known_bad_ip",
    "recon_commands",
    "persistence_attempt",
    "data_exfil_attempt",
    "malware_dropped",
    "multi_protocol",
]

DOWNLOAD_PATTERNS = ("wget", "curl", "tftp")
PRIV_ESC_PATTERNS = ("sudo", " su", "chmod 777", "passwd")
RECON_PATTERNS = ("id", "whoami", "uname", "hostname", "ifconfig", "ip a")
PERSISTENCE_PATTERNS = ("crontab", ".bashrc", "systemctl", "service")
EXFIL_PATTERNS = ("scp", "rsync", "base64", "cat /etc/passwd")


def _normalize_commands(commands: list[dict[str, Any]] | None) -> list[str]:
    if not commands:
        return []
    return [str(item.get("command", "")).lower() for item in commands if isinstance(item, dict)]


def _duration_seconds(start_time: datetime | None, end_time: datetime | None) -> float:
    if not start_time:
        return 0.0
    end = end_time or datetime.now(timezone.utc)
    if start_time.tzinfo is None:
        start_time = start_time.replace(tzinfo=timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    return max((end - start_time).total_seconds(), 0.0)


def extract_features(session: Any, profile: Any, multi_protocol: bool = False, known_bad_ip: bool = False) -> list[float]:
    commands = _normalize_commands(getattr(session, "commands", []))
    cmd_count = float(len(commands))

    unique_cmd_ratio = float(len(set(commands)) / len(commands)) if commands else 0.0
    download_attempt = float(any(any(p in cmd for p in DOWNLOAD_PATTERNS) for cmd in commands))
    priv_escalation_attempt = float(any(any(p in cmd for p in PRIV_ESC_PATTERNS) for cmd in commands))

    credentials = getattr(session, "credentials_tried", []) or []
    failed_logins = 0
    for cred in credentials:
        if isinstance(cred, dict) and not cred.get("success", False):
            failed_logins += 1
    credential_spray = float(failed_logins > 3)

    start_time = getattr(session, "start_time", None)
    end_time = getattr(session, "end_time", None)
    duration = _duration_seconds(start_time, end_time)
    commands_per_minute = float(cmd_count / max(duration / 60.0, 1e-6)) if cmd_count else 0.0

    st = start_time or datetime.now(timezone.utc)
    if st.tzinfo is None:
        st = st.replace(tzinfo=timezone.utc)
    hour_of_day = float(st.hour)
    is_weekend = float(st.weekday() >= 5)

    vpn_detected = float(bool(getattr(profile, "vpn_detected", False)))
    known_bad = float(bool(known_bad_ip))

    recon_commands = float(sum(1 for cmd in commands if any(p in cmd for p in RECON_PATTERNS)))
    persistence_attempt = float(sum(1 for cmd in commands if any(p in cmd for p in PERSISTENCE_PATTERNS)))
    data_exfil_attempt = float(sum(1 for cmd in commands if any(p in cmd for p in EXFIL_PATTERNS)))

    malware_hashes = getattr(session, "malware_hashes", []) or []
    malware_dropped = float(len(malware_hashes) > 0)

    return [
        cmd_count,
        unique_cmd_ratio,
        download_attempt,
        priv_escalation_attempt,
        credential_spray,
        float(duration),
        commands_per_minute,
        hour_of_day,
        is_weekend,
        vpn_detected,
        known_bad,
        recon_commands,
        persistence_attempt,
        data_exfil_attempt,
        malware_dropped,
        float(multi_protocol),
    ]
