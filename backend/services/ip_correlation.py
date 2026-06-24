"""
Real-IP correlation for SSH-gateway-proxied honeypot sessions.

The SSH gateway is a man-in-the-middle: it terminates the attacker's connection
and re-originates a fresh SSH connection to Cowrie, so Cowrie logs the *gateway's*
container IP as the source. The gateway, however, knows the real attacker IP and
the local (outbound) TCP port it used to reach Cowrie.

Cowrie records that same port as ``src_port`` on its ``cowrie.session.connect``
event. We therefore map ``gateway_outbound_port -> real_ip`` (reported by the
gateway) and, once a connect event resolves it, remember
``cowrie_session_id -> real_ip`` so the session's later (port-less) events are
attributed to the real attacker too.

All state is in-process (the log tailer and the routing endpoint run in the same
backend process) with a short TTL so stale ports are not reused.
"""
from __future__ import annotations

import os
import threading
import time

PROXY_MAP_TTL = int(os.getenv("PROXY_MAP_TTL", "600"))

_lock = threading.Lock()
_proxy_port_map: dict[int, dict] = {}   # gateway_outbound_port -> {real_ip, expires_at}
_session_real_ip: dict[str, dict] = {}  # cowrie session id -> {real_ip, expires_at}


def _prune(now: float) -> None:
    for store in (_proxy_port_map, _session_real_ip):
        for key in [k for k, v in store.items() if v["expires_at"] <= now]:
            store.pop(key, None)


def register_proxy_mapping(proxy_port: int, real_ip: str, ttl: int = PROXY_MAP_TTL) -> None:
    """Record that the gateway's outbound port ``proxy_port`` corresponds to a
    connection from real attacker ``real_ip``. Called from the routing endpoint."""
    if not proxy_port or not real_ip:
        return
    now = time.time()
    with _lock:
        _proxy_port_map[int(proxy_port)] = {"real_ip": real_ip, "expires_at": now + max(ttl, 1)}
        _prune(now)


def resolve_for_connect(proxy_port: int, cowrie_session: str | None, ttl: int = PROXY_MAP_TTL) -> str | None:
    """Resolve the real IP for a ``cowrie.session.connect`` event by its
    ``src_port`` and remember it for the session's subsequent events. The
    port entry is single-use and removed once consumed."""
    if not proxy_port:
        return None
    now = time.time()
    with _lock:
        entry = _proxy_port_map.pop(int(proxy_port), None)
        if not entry or entry["expires_at"] <= now:
            return None
        real_ip = entry["real_ip"]
        if cowrie_session:
            _session_real_ip[str(cowrie_session)] = {"real_ip": real_ip, "expires_at": now + max(ttl, 1)}
        return real_ip


def resolve_for_session(cowrie_session: str | None) -> str | None:
    """Resolve the real IP for a non-connect event using the session id."""
    if not cowrie_session:
        return None
    now = time.time()
    with _lock:
        entry = _session_real_ip.get(str(cowrie_session))
        if not entry or entry["expires_at"] <= now:
            return None
        return entry["real_ip"]
