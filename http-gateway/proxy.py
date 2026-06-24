"""
EvilTwin HTTP Gateway — credential-gated routing for HTTP/HTTPS traffic.

Same pattern as the SSH gateway: the real server is HIDDEN by default.
Every unauthenticated client (including port scanners) is served a
deceptive honeypot page. The real server is only reachable when the
correct credentials (real / eviltwin) are presented — exactly like the
SSH gateway's credential fast-path.

Architecture:
  Client → HTTP Gateway (port 80)
    ├─ valid creds (Basic-Auth header OR portal login form) → real proxy
    ├─ signed auth cookie from a prior successful login    → real proxy
    ├─ backend decision == "real" (set by SSH credential match) → real proxy
    └─ everything else (unknown / scanner / wrong creds) → honeypot.html
            └─ POST creds → backend:8000/log (ingested to DB)

DEFAULT DENY: an unknown IP NEVER reaches the real server. The real
server stays isolated behind the credential gate.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import secrets

import aiohttp
from aiohttp import web

BACKEND_URL = os.getenv("ROUTING_BACKEND_URL", "http://backend:8000")
REAL_SERVER_URL = os.getenv("REAL_HTTP_URL", "http://dummy-real:8080")
LISTEN_PORT = int(os.getenv("HTTP_GATEWAY_PORT", "80"))
ROUTING_API_KEY = os.getenv("ROUTING_API_KEY", "").strip()
INGEST_BACKEND_URL = os.getenv("INGEST_BACKEND_URL", BACKEND_URL)

# Credential gate — must match the correct user/password to reach the real server.
REAL_HTTP_USER = os.getenv("REAL_HTTP_USER", "real")
REAL_HTTP_PASSWORD = os.getenv("REAL_HTTP_PASSWORD", "eviltwin")

# Signed-cookie config so an authenticated browser session keeps reaching the
# real server without re-submitting credentials on every request.
AUTH_COOKIE_NAME = os.getenv("AUTH_COOKIE_NAME", "et_sess")
AUTH_TTL_S = int(os.getenv("AUTH_TTL_S", "3600"))
_SECRET_KEY = os.getenv("SECRET_KEY", "").strip() or secrets.token_hex(32)

BYPASS_IPS = {"127.0.0.1", "::1", "::ffff:127.0.0.1"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [HTTP-GW] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("http-gateway")

HONEYPOT_HTML: bytes = b""


def _load_honeypot() -> bytes:
    path = os.path.join(os.path.dirname(__file__), "static", "honeypot.html")
    if not os.path.exists(path):
        path = os.path.join(os.path.dirname(__file__), "honeypot.html")
    try:
        with open(path, "rb") as f:
            return f.read()
    except FileNotFoundError:
        return b"<html><body><h1>Service Unavailable</h1></body></html>"


def _is_bypass(ip: str) -> bool:
    return ip in BYPASS_IPS or ip.startswith("127.")


def _auth_token() -> str:
    """Stateless HMAC token proving a successful credential check."""
    return hmac.new(
        _SECRET_KEY.encode(), b"http-real-auth", hashlib.sha256
    ).hexdigest()


def _has_valid_cookie(request: web.Request) -> bool:
    token = request.cookies.get(AUTH_COOKIE_NAME, "")
    if not token:
        return False
    return hmac.compare_digest(token, _auth_token())


def _credentials_match(username: str, password: str) -> bool:
    user_ok = hmac.compare_digest(username or "", REAL_HTTP_USER)
    pass_ok = hmac.compare_digest(password or "", REAL_HTTP_PASSWORD)
    return user_ok and pass_ok


def _check_basic_auth(request: web.Request) -> bool:
    header = request.headers.get("Authorization", "")
    if not header.lower().startswith("basic "):
        return False
    try:
        raw = base64.b64decode(header.split(" ", 1)[1].strip()).decode("utf-8")
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return False
    username, _, password = raw.partition(":")
    return _credentials_match(username, password)


async def _get_routing(client_ip: str) -> str:
    if _is_bypass(client_ip):
        return "real"

    headers = {"X-Routing-Key": ROUTING_API_KEY} if ROUTING_API_KEY else {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"{BACKEND_URL}/routing/decision/{client_ip}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=3),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("decision", "unknown")
    except Exception as exc:
        logger.warning("Routing lookup failed for %s: %s", client_ip, exc)
    return "unknown"


async def _notify_routing(client_ip: str) -> None:
    """Mark this IP as 'real' in the backend routing table (mirrors SSH gateway)."""
    if _is_bypass(client_ip):
        return
    headers = {"X-Routing-Key": ROUTING_API_KEY} if ROUTING_API_KEY else {}
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{BACKEND_URL}/routing/decision",
                json={"ip": client_ip, "target": "real", "duration": 300},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=3),
            )
    except Exception:
        pass  # fire-and-forget


async def _proxy_to_real(
    request: web.Request, set_auth_cookie: bool = False
) -> web.StreamResponse:
    target_url = f"{REAL_SERVER_URL}{request.path_qs}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.request(
                method=request.method,
                url=target_url,
                headers={k: v for k, v in request.headers.items()
                         if k.lower() not in ("host", "authorization")},
                data=await request.read(),
                timeout=aiohttp.ClientTimeout(total=10),
            ) as upstream:
                resp = web.StreamResponse(
                    status=upstream.status,
                    headers={k: v for k, v in upstream.headers.items()
                             if k.lower() not in ("transfer-encoding", "content-encoding")},
                )
                if set_auth_cookie:
                    _set_auth_cookie(resp)
                await resp.prepare(request)
                async for chunk in upstream.content.iter_any():
                    await resp.write(chunk)
                return resp
    except Exception as exc:
        logger.warning("Proxy to real server failed: %s", exc)
        return web.Response(status=502, text="Gateway error")


def _set_auth_cookie(resp: web.StreamResponse) -> None:
    resp.set_cookie(
        AUTH_COOKIE_NAME,
        _auth_token(),
        max_age=AUTH_TTL_S,
        httponly=True,
        samesite="Lax",
    )


async def _ingest_honeypot_creds(client_ip: str, post_data: dict) -> None:
    """Fire-and-forget POST credentials to backend /log for DB ingestion."""
    import uuid
    session_id = str(uuid.uuid4())
    try:
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{INGEST_BACKEND_URL}/log",
                json={
                    "eventid": f"dionaea-http-{client_ip}-80-127.0.0.1-80-000000",
                    "src_ip": client_ip,
                    "src_port": 0,
                    "dst_ip": "10.0.2.10",
                    "dst_port": 80,
                    "protocol": "http",
                    "honeypot": "dionaea",
                    "session": session_id,
                    "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
                    "credentials": {
                        "username": post_data.get("username", ""),
                        "password": post_data.get("password", ""),
                    },
                },
                timeout=aiohttp.ClientTimeout(total=3),
            )
    except Exception:
        pass  # fire-and-forget — don't block the response


def _serve_honeypot_page() -> web.Response:
    return web.Response(
        body=HONEYPOT_HTML,
        content_type="text/html",
        charset="utf-8",
        headers={"Server": "Microsoft-IIS/10.0"},
    )


async def handle(request: web.Request) -> web.StreamResponse | web.Response:
    client_ip = request.remote or "unknown"

    # Loopback / local development always reaches the real server.
    if _is_bypass(client_ip):
        return await _proxy_to_real(request)

    # 1) Already-authenticated browser session.
    if _has_valid_cookie(request):
        logger.info("%s → REAL (valid session cookie)", client_ip)
        return await _proxy_to_real(request)

    # 2) HTTP Basic-Auth credentials (e.g. curl -u real:eviltwin).
    if _check_basic_auth(request):
        logger.info("%s → REAL (basic-auth credential match)", client_ip)
        import asyncio
        asyncio.get_running_loop().create_task(_notify_routing(client_ip))
        return await _proxy_to_real(request, set_auth_cookie=True)

    # 3) Portal login form submission.
    if request.method == "POST":
        post_data = dict(await request.post())
        username = post_data.get("username", "")
        password = post_data.get("password", "")

        if _credentials_match(username, password):
            logger.info("%s → REAL (portal credential match, user=%s)", client_ip, username)
            import asyncio
            asyncio.get_running_loop().create_task(_notify_routing(client_ip))
            resp = web.HTTPFound("/")
            _set_auth_cookie(resp)
            return resp

        # Wrong credentials → capture and keep up the deception.
        logger.info("HONEYPOT CAPTURE | %s | %s | user=%s",
                    client_ip, request.path, username or "?")
        import asyncio
        asyncio.get_running_loop().create_task(
            _ingest_honeypot_creds(client_ip, post_data)
        )
        return _serve_honeypot_page()

    # 4) DEFAULT DENY. Only an explicit backend "real" decision (set by the
    #    SSH gateway credential match) bypasses the portal. Everything else —
    #    unknown IPs, scanners — gets the honeypot. The real server stays hidden.
    decision = await _get_routing(client_ip)
    if decision == "real":
        logger.info("%s → REAL (backend authorized)", client_ip)
        return await _proxy_to_real(request)

    logger.info("%s → HONEYPOT (fake OWA portal, decision=%s)", client_ip, decision)
    return _serve_honeypot_page()


async def healthz(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "service": "http-gateway"})


def main() -> None:
    global HONEYPOT_HTML
    HONEYPOT_HTML = _load_honeypot()

    app = web.Application(client_max_size=10 * 1024 * 1024)  # 10MB limit
    app.router.add_get("/healthz", healthz)
    app.router.add_route("*", "/{tail:.*}", handle)
    logger.info("HTTP Gateway starting on port %s", LISTEN_PORT)
    logger.info("  Backend:   %s", BACKEND_URL)
    logger.info("  Real:      %s (credential-gated, hidden by default)", REAL_SERVER_URL)
    logger.info("  Gate user: %s", REAL_HTTP_USER)
    logger.info("  Bypass:    %s", sorted(BYPASS_IPS))

    web.run_app(app, host="0.0.0.0", port=LISTEN_PORT, print=None)


if __name__ == "__main__":
    main()
