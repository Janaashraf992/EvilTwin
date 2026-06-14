"""
EvilTwin Tripwire Service
- Runs an HTTP file server on port 8080 exposing bait files (simulates a misconfigured server)
- Monitors filesystem for direct access via inotify
- Any HTTP request or file access fires a canary webhook alert
"""
import hashlib
import hmac
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
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

_last_triggered: dict[str, float] = {}


def compute_signature(payload: str) -> str:
    return hmac.new(
        WEBHOOK_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def fire_webhook(event_path: str, event_type: str, src_ip: str = "", user_agent: str = "") -> bool:
    now = time.time()
    key = f"{event_path}_{event_type}"
    if key in _last_triggered:
        if now - _last_triggered[key] < COOLDOWN_SECONDS:
            return False

    _last_triggered[key] = now

    if not src_ip:
        try:
            src_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            src_ip = "127.0.0.1"

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ua = user_agent or f"tripwire/{event_type}:{os.path.basename(event_path)}"
    body = {
        "token_id": TOKEN_ID,
        "timestamp": ts,
        "src_ip": src_ip,
        "user_agent": ua,
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
        if event.event_type in ("opened", "modified", "moved", "deleted", "created", "closed"):
            logger.info("TRIGGERED: %s -> %s", event.event_type, event.src_path)
            fire_webhook(event.src_path, event.event_type)


# ---------------------------------------------------------------------------
# HTTP honeypot file server  (simulates misconfigured exposed directory)
# ---------------------------------------------------------------------------
class BaitHTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WATCH_DIR, **kwargs)

    def do_GET(self):
        client_ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "Unknown")
        path = self.path or "/"

        logger.info("HTTP ACCESS: %s from %s [%s]", path, client_ip, user_agent)

        # Ignore favicon / robots.txt noise but still log
        if path not in ("/favicon.ico", "/robots.txt"):
            fire_webhook(
                f"http://{client_ip}{path}",
                "http_get",
                src_ip=client_ip,
                user_agent=user_agent,
            )

        super().do_GET()

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
    if not TOKEN_ID:
        logger.error("CANARY_TOKEN_ID not set. Create a token in the dashboard and set the env var.")
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
    logger.info(" Token ID:     %s", TOKEN_ID)
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
