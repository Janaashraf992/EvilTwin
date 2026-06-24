"""
EvilTwin Tripwire Service
- Runs an HTTP file server on port 8080 exposing bait files (simulates a misconfigured server)
- Monitors filesystem for direct access via inotify
- Any HTTP request or file access fires a canary webhook alert
- Supports per-path token mapping via TOKEN_MAP env var (JSON)
"""
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

CAIRO_TZ = ZoneInfo("Africa/Cairo")
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

import httpx
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

logging.basicConfig(level=logging.INFO, format="%(asctime)s [TRIPWIRE] %(message)s")
logger = logging.getLogger(__name__)

WEBHOOK_URL = os.environ.get("CANARY_WEBHOOK_URL", "http://backend:8000/webhook/canary")
WEBHOOK_SECRET = os.environ.get("CANARY_WEBHOOK_SECRET", "change-me-in-production")
TOKEN_ID = os.environ.get("CANARY_TOKEN_ID", "")
WATCH_DIR = os.environ.get("WATCH_DIR", "/bait")
COOLDOWN_SECONDS = int(os.environ.get("COOLDOWN_SECONDS", "30"))
HTTP_PORT = int(os.environ.get("TRIPWIRE_HTTP_PORT", "8080"))

_raw_map = os.environ.get("TOKEN_MAP", "{}")
try:
    TOKEN_MAP: dict[str, str] = json.loads(_raw_map)
except json.JSONDecodeError:
    logger.warning("TOKEN_MAP is not valid JSON; using empty mapping")
    TOKEN_MAP = {}

_last_triggered: dict[str, float] = {}
_trigger_lock = threading.Lock()


def _resolve_token_id(http_path: str) -> str:
    normalized = http_path.rstrip("/") or "/"
    if normalized in TOKEN_MAP:
        return TOKEN_MAP[normalized]
    if TOKEN_MAP.get("default"):
        return TOKEN_MAP["default"]
    return TOKEN_ID


def compute_signature(payload: str) -> str:
    return hmac.new(
        WEBHOOK_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def fire_webhook(event_path: str, event_type: str, src_ip: str = "", user_agent: str = "", token_id: str = "") -> bool:
    now = time.time()
    key = f"{event_path}_{event_type}"
    with _trigger_lock:
        if key in _last_triggered:
            if now - _last_triggered[key] < COOLDOWN_SECONDS:
                return False
        _last_triggered[key] = now

    effective_token = token_id or TOKEN_ID

    if not src_ip:
        try:
            src_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            src_ip = "127.0.0.1"

    ts = datetime.now(CAIRO_TZ).isoformat()
    ua = user_agent or f"tripwire/{event_type}:{os.path.basename(event_path)}"
    body = {
        "token_id": effective_token,
        "timestamp": ts,
        "src_ip": src_ip,
        "user_agent": ua,
        "nonce": uuid.uuid4().hex,
        "signature": ""
    }
    payload = json.dumps(body, separators=(",", ":"))
    sig = compute_signature(payload)

    try:
        resp = httpx.post(
            WEBHOOK_URL,
            content=payload,
            headers={
                "Content-Type": "application/json",
                "X-Signature": sig,
            },
            timeout=5.0,
        )
        if resp.status_code < 300:
            logger.info("ALERT FIRED: %s [%s] src=%s", event_path, event_type, src_ip)
            return True
        else:
            logger.warning("Webhook returned %d: %s", resp.status_code, resp.text)
            return False
    except Exception as e:
        logger.error("Failed to fire webhook: %s", e)
        return False


# ---------------------------------------------------------------------------
# Inotify file watcher
# ---------------------------------------------------------------------------
class TripwireHandler(FileSystemEventHandler):
    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        # Only react to tampering. "opened"/"closed" events are also emitted when
        # this process serves a file over HTTP, which would double-fire alongside
        # the do_GET webhook — so they are intentionally excluded.
        if event.event_type in ("modified", "moved", "deleted", "created"):
            logger.info("TRIGGERED: %s -> %s", event.event_type, event.src_path)
            rel = str(Path(event.src_path).relative_to(WATCH_DIR))
            http_path = "/" + rel.replace("\\", "/")
            token_id = _resolve_token_id(http_path)
            fire_webhook(
                event.src_path,
                f"fs_{event.event_type}",
                token_id=token_id,
            )


# ---------------------------------------------------------------------------
# HTTP honeypot file server  (simulates misconfigured exposed directory)
# ---------------------------------------------------------------------------
class BaitHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WATCH_DIR, **kwargs)

    def do_GET(self):
        client_ip = self._client_ip()
        user_agent = self.headers.get("User-Agent", "Unknown")
        path = self.path or "/"

        logger.info("HTTP ACCESS: %s from %s [%s]", path, client_ip, user_agent)

        if path not in ("/favicon.ico", "/robots.txt"):
            token_id = _resolve_token_id(path)
            fire_webhook(
                f"http://{client_ip}{path}",
                "http_get",
                src_ip=client_ip,
                user_agent=user_agent,
                token_id=token_id,
            )

        super().do_GET()

    def list_directory(self, path):
        # Autoindex is disabled: the only openly discoverable bait is the benign
        # index page (the "Public Web Bug"). Higher-difficulty baits live at
        # explicit, unlisted paths (e.g. /.git/, /.env.production) so they must
        # be discovered, not browsed.
        self.send_error(404, "Not Found")
        return None

    def _client_ip(self) -> str:
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = self.headers.get("X-Real-IP", "")
        if real_ip:
            return real_ip.strip()
        return self.client_address[0]

    def log_message(self, format, *args):
        pass  # We log via the standard logger already


def run_http_server(port: int):
    server = HTTPServer(("0.0.0.0", port), BaitHTTPHandler)
    logger.info("HTTP bait server listening on http://0.0.0.0:%d", port)
    server.serve_forever()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    if not TOKEN_ID and not TOKEN_MAP.get("default"):
        logger.error("Neither CANARY_TOKEN_ID nor TOKEN_MAP.default is set. Create a token in the dashboard and set the env vars.")
        return

    watch_path = Path(WATCH_DIR)
    if not watch_path.exists():
        logger.error("Watch directory does not exist: %s", WATCH_DIR)
        return

    bait_files = list(watch_path.rglob("*"))
    for f in sorted(bait_files):
        if f.is_file():
            logger.info("  Bait: /%s", f.relative_to(watch_path))

    logger.info("=" * 60)
    logger.info("TRIPWIRE LIVE")
    logger.info(" HTTP server:  http://0.0.0.0:%d  (exposed bait files)", HTTP_PORT)
    logger.info(" File watch:   %s", WATCH_DIR)
    logger.info(" Webhook:      %s", WEBHOOK_URL)
    logger.info(" Default token: %s", TOKEN_MAP.get("default", TOKEN_ID))
    if TOKEN_MAP:
        logger.info(" Path→Token mappings:")
        for path, tid in sorted(TOKEN_MAP.items()):
            if path != "default":
                logger.info("   %-30s → %s", path, tid)
    logger.info("=" * 60)

    # Start HTTP server in background thread
    http_thread = threading.Thread(target=run_http_server, args=(HTTP_PORT,), daemon=True)
    http_thread.start()

    # Start inotify file watcher
    observer = Observer()
    observer.schedule(TripwireHandler(), str(watch_path), recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
