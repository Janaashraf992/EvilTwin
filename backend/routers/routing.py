"""
Per-IP routing decisions — in-memory with file persistence.

Stores routing decisions from the SSH gateway so the HTTP gateway
can route traffic consistently for the same IP.  Survives restarts
via JSON file, cleans up expired entries automatically, and supports
an optional API key for protection.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from fastapi import APIRouter, Header, HTTPException

from services.ip_correlation import PROXY_MAP_TTL, register_proxy_mapping

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/routing", tags=["routing"])

ROUTING_FILE = os.getenv("ROUTING_PERSIST_FILE", "/tmp/routing.json")
ROUTING_API_KEY = os.getenv("ROUTING_API_KEY", "").strip()
ROUTING_BYPASS_IPS = os.getenv("ROUTING_BYPASS_IPS", "127.0.0.1,::1").strip()

DEFAULT_TTL = 300  # 5 minutes
REAL_SERVER_IP = "dummy-real"
HONEYPOT_IP = "dionaea"

_routing_table: dict[str, dict] = {}
_save_lock = asyncio.Lock()
_dirty = False
_bypass_ips: set[str] = set()

# ---- Auth helper ----
def _check_auth(key: str = Header("", alias="X-Routing-Key")) -> None:
    if ROUTING_API_KEY and key != ROUTING_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid routing key")

# ---- Persistence ----
def _file_path() -> str:
    return ROUTING_FILE

def _load_from_file() -> None:
    global _bypass_ips
    _bypass_ips = {ip.strip() for ip in ROUTING_BYPASS_IPS.split(",") if ip.strip()}
    try:
        if os.path.exists(_file_path()):
            with open(_file_path(), "r") as f:
                data = json.load(f)
            now = time.time()
            count = 0
            for ip, entry in data.items():
                if entry.get("expires_at", 0) > now:
                    _routing_table[ip] = entry
                    count += 1
            if count:
                logger.info("Loaded %d routing entries from %s", count, _file_path())
    except Exception as exc:
        logger.warning("Failed to load routing file: %s", exc)

def _save_to_file() -> None:
    try:
        os.makedirs(os.path.dirname(_file_path()), exist_ok=True)
        with open(_file_path(), "w") as f:
            json.dump(_routing_table, f)
    except Exception as exc:
        logger.warning("Failed to save routing file: %s", exc)

async def _cleanup_loop() -> None:
    global _dirty
    while True:
        await asyncio.sleep(60)
        now = time.time()
        to_delete = [ip for ip, e in _routing_table.items() if e["expires_at"] <= now]
        if to_delete:
            for ip in to_delete:
                _routing_table.pop(ip, None)
            _dirty = True
            logger.debug("Cleaned up %d expired routing entries", len(to_delete))
        if _dirty:
            async with _save_lock:
                if _dirty:
                    _save_to_file()
                    _dirty = False

# Load on import, start cleanup
_load_from_file()
_cleanup_task: asyncio.Task | None = None


@router.on_event("startup")
async def _start_cleanup() -> None:
    global _cleanup_task
    if _cleanup_task is None:
        _cleanup_task = asyncio.create_task(_cleanup_loop())


@router.on_event("shutdown")
async def _stop_cleanup() -> None:
    global _cleanup_task
    if _cleanup_task:
        _cleanup_task.cancel()
        _cleanup_task = None


# ---- API endpoints ----
@router.post("/decision")
async def set_routing(data: dict, _key: str = Header("", alias="X-Routing-Key")) -> dict:
    _check_auth(_key)
    global _dirty
    ip = data.get("ip", "").strip()
    target = data.get("target", "").strip()
    if not ip or not target:
        return {"status": "error", "detail": "missing ip or target"}

    target_ip = REAL_SERVER_IP if target == "real" else HONEYPOT_IP
    _routing_table[ip] = {
        "target": target,
        "target_ip": target_ip,
        "expires_at": time.time() + data.get("duration", DEFAULT_TTL),
    }
    _dirty = True
    async with _save_lock:
        _save_to_file()
    _dirty = False
    return {"status": "ok", "ip": ip, "target": target, "target_ip": target_ip}


@router.post("/proxy-map")
async def set_proxy_map(data: dict, _key: str = Header("", alias="X-Routing-Key")) -> dict:
    """Register that the SSH gateway's outbound port maps to a real attacker IP.

    The gateway proxies SSH to Cowrie, so Cowrie logs the gateway IP. Cowrie
    records the gateway's outbound port as ``src_port`` on its connect event;
    ingestion uses this mapping to attribute the session to the real client."""
    _check_auth(_key)
    proxy_port = data.get("proxy_port")
    real_ip = (data.get("real_ip") or "").strip()
    if not proxy_port or not real_ip:
        return {"status": "error", "detail": "missing proxy_port or real_ip"}
    ttl = int(data.get("ttl") or PROXY_MAP_TTL)
    register_proxy_mapping(int(proxy_port), real_ip, ttl)
    return {"status": "ok", "proxy_port": int(proxy_port), "real_ip": real_ip}


@router.get("/decision/{ip}")
async def get_routing(ip: str, _key: str = Header("", alias="X-Routing-Key")) -> dict:
    _check_auth(_key)
    if ip in _bypass_ips:
        return {"ip": ip, "decision": "real", "target_ip": REAL_SERVER_IP, "bypass": True}

    now = time.time()
    entry = _routing_table.get(ip)
    if entry and entry["expires_at"] > now:
        return {
            "ip": ip,
            "decision": entry["target"],
            "target_ip": entry["target_ip"],
            "expires_in": int(entry["expires_at"] - now),
        }
    _routing_table.pop(ip, None)
    return {"ip": ip, "decision": "unknown", "target_ip": None}
