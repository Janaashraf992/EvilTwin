from __future__ import annotations

import ipaddress
import time
from typing import Optional

KNOWN_SCANNER_CIDRS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("45.33.32.0/24"),
    ipaddress.ip_network("167.248.133.0/24"),
    ipaddress.ip_network("71.6.232.0/24"),
    ipaddress.ip_network("71.6.233.0/24"),
    ipaddress.ip_network("66.240.192.0/18"),
    ipaddress.ip_network("66.240.236.0/24"),
    ipaddress.ip_network("74.82.47.0/24"),
    ipaddress.ip_network("162.142.125.0/24"),
    ipaddress.ip_network("167.94.138.0/24"),
    ipaddress.ip_network("167.94.145.0/24"),
    ipaddress.ip_network("167.94.146.0/24"),
    ipaddress.ip_network("184.105.139.0/24"),
    ipaddress.ip_network("184.105.247.0/24"),
    ipaddress.ip_network("192.35.168.0/23"),
    ipaddress.ip_network("206.168.34.0/24"),
    ipaddress.ip_network("64.62.197.0/24"),
    ipaddress.ip_network("141.212.120.0/24"),
    ipaddress.ip_network("141.212.121.0/24"),
    ipaddress.ip_network("141.212.122.0/24"),
]

DEPRECATED_CLIENT_PATTERNS: list[str] = [
    "libssh-0.",
    "libssh-1.",
    "SSH-1.",
    "PuTTY-Release-0.",
    "ZGrab",
    "Zgrab",
    "paramiko_",
    "go-ssh-0.",
    "node-ssh",
]

SUSPICIOUS_USERNAMES: set[str] = {
    "root", "admin", "administrator", "oracle", "postgres", "mysql",
    "tomcat", "jenkins", "pi", "ubuntu", "debian", "centos",
    "test", "guest", "ftp", "www-data", "git", "svn", "deploy",
    "nagios", "zabbix", "backup", "user",
}

SAFE_COMMAND_PATTERNS: list[str] = [
    r"^(ls|dir|pwd|whoami|id|uname|hostname|date|uptime|df|free|ps|top)\b",
    r"^echo\b",
    r"^cat\s+(?!.*[><|;&]).+$",
    r"^head\b",
    r"^tail\b",
    r"^systemctl\s+status\b",
    r"^journalctl\b",
    r"^netstat\b",
    r"^ss\b",
    r"^ip\s+(addr|link|route)\b",
    r"^(git|svn)\b",
    r"^(docker|podman)\b",
    r"^(kubectl|helm|terraform)\b",
    r"^(rsync|scp)\b",
    r"^(npm|yarn|pip|cargo|go)\b",
    r"^python3?\s+-m\b",
    r"^(make|cmake|ninja)\b",
    r"^(systemctl|service)\s+(start|stop|restart|reload)\b",
    r"^(deploy|release)\b",
]

SUSPICIOUS_COMMAND_PATTERNS: list[str] = [
    r"rm\s+-rf",
    r"wget\s+http",
    r"curl\s+.*\|.*sh",
    r"chmod\s+777",
    r"/etc/(shadow|passwd)",
    r"nc\s+-e",
    r"python\s+-c.*socket",
    r"base64\s+-d",
    r">/dev/tcp/",
    r"dd\s+if=",
]


class ConnectionHistory:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self._records: dict[str, list[float]] = {}
        self._ttl = ttl_seconds

    def record_connect(self, ip: str) -> None:
        now = time.monotonic()
        if ip not in self._records:
            self._records[ip] = []
        self._records[ip].append(now)
        self._records[ip] = [
            t for t in self._records[ip] if now - t < self._ttl
        ]

    def recent_connections(self, ip: str) -> int:
        now = time.monotonic()
        if ip not in self._records:
            return 0
        self._records[ip] = [
            t for t in self._records[ip] if now - t < self._ttl
        ]
        if not self._records[ip]:
            del self._records[ip]
            return 0
        return len(self._records[ip])

    def was_recent_reconnect(self, ip: str, window: float = 60.0) -> bool:
        now = time.monotonic()
        if ip not in self._records:
            return False
        records = [t for t in self._records[ip] if now - t < self._ttl]
        self._records[ip] = records
        if len(records) >= 2:
            if records[-1] - records[-2] < window:
                return True
        return False


_connection_history: Optional[ConnectionHistory] = None


def get_connection_history() -> ConnectionHistory:
    global _connection_history
    if _connection_history is None:
        _connection_history = ConnectionHistory(ttl_seconds=300)
    return _connection_history


def is_known_scanner(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        for cidr in KNOWN_SCANNER_CIDRS:
            if ip in cidr:
                return True
    except ValueError:
        pass
    return False


def is_in_cidr_list(ip_str: str, cidr_list: str) -> bool:
    if not cidr_list.strip():
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        for entry in cidr_list.split(","):
            entry = entry.strip()
            if not entry:
                continue
            if ip in ipaddress.ip_network(entry):
                return True
    except ValueError:
        pass
    return False


def is_deprecated_client(version: str) -> bool:
    for pattern in DEPRECATED_CLIENT_PATTERNS:
        if pattern in version:
            return True
    return False


def is_suspicious_username(username: str) -> bool:
    return username.lower() in SUSPICIOUS_USERNAMES


def has_any_suspicious_username(usernames: list[str]) -> bool:
    return any(is_suspicious_username(u) for u in usernames)


def match_any_pattern(text: str, patterns: list[str]) -> bool:
    import re
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            return True
    return False
