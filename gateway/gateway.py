from __future__ import annotations

import asyncio
import logging
import os
import signal
import time
from typing import Optional

import asyncssh

from session_signals import SessionSignals

logger = logging.getLogger("eviltwin.gateway")

BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")
REAL_SSH_HOST = os.getenv("REAL_SSH_HOST", "10.0.1.20")
REAL_SSH_PORT = int(os.getenv("REAL_SSH_PORT", "22"))
REAL_SSH_USER = os.getenv("REAL_SSH_USER", "")
REAL_SSH_PASSWORD = os.getenv("REAL_SSH_PASSWORD", "")
HONEYPOT_HOST = os.getenv("HONEYPOT_HOST", "cowrie")
HONEYPOT_PORT = int(os.getenv("HONEYPOT_PORT", "2222"))
AUTH_COLLECT_WINDOW_S = float(os.getenv("AUTH_COLLECT_WINDOW_S", "5.0"))
BACKEND_TIMEOUT = float(os.getenv("BACKEND_TIMEOUT", "2.0"))
GATEWAY_LISTEN_PORT = int(os.getenv("GATEWAY_LISTEN_PORT", "22"))
HOST_KEY_PATH = os.getenv("HOST_KEY_PATH", "/etc/eviltwin/ssh_host_rsa_key")

SUSPICIOUS_USERNAMES = {
    "root", "admin", "administrator", "test", "guest", "user",
    "ubuntu", "debian", "centos", "pi", "oracle", "postgres",
    "mysql", "tomcat", "jenkins", "git", "svn", "deploy",
    "nagios", "zabbix", "backup", "ftp", "www", "www-data",
}


class _RelayClientSession(asyncssh.SSHClientSession):
    def __init__(self, server_chan: asyncssh.SSHServerChannel):
        self._server_chan = server_chan

    def data_received(self, data, datatype) -> None:
        if self._server_chan is None or self._server_chan.is_closing():
            return
        try:
            if datatype == asyncssh.EXTENDED_DATA_STDERR:
                self._server_chan.write_stderr(data)
            else:
                self._server_chan.write(data)
        except Exception:
            pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._server_chan is not None and not self._server_chan.is_closing():
            try:
                self._server_chan.write_eof()
            except Exception:
                pass


class GatewaySession(asyncssh.SSHServerSession):
    def __init__(self, signals: SessionSignals, server: "GatewayServer"):
        self._signals = signals
        self._server = server
        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._ssh_conn: Optional[asyncssh.SSHClientConnection] = None
        self._proxy_lock = asyncio.Lock()
        self._upstream_chan: Optional[asyncssh.SSHClientChannel] = None
        self._pre_buffer: list = []
        self._term_type: str = "xterm-256color"
        self._term_size: tuple[int, int, int, int] = (80, 24, 0, 0)

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan

    def data_received(self, data, datatype) -> None:
        if self._upstream_chan is not None:
            try:
                self._upstream_chan.write(data)
            except Exception:
                pass
        else:
            self._pre_buffer.append(data)

    def eof_received(self) -> bool:
        if self._upstream_chan is not None:
            try:
                self._upstream_chan.write_eof()
            except Exception:
                pass
        return False

    def pty_requested(
        self,
        term_type: str,
        term_size: tuple[int, int, int, int],
        term_modes: dict[int, int],
    ) -> bool:
        self._term_type = term_type or "xterm-256color"
        self._term_size = term_size
        return True

    def shell_requested(self) -> bool:
        self._signals.record_session_request(term="")
        return True

    def exec_requested(self, command: str) -> bool:
        self._signals.record_session_request(command=command)
        return True

    def subsystem_requested(self, subsystem: str) -> bool:
        return False

    def session_started(self) -> None:
        if self._chan is not None:
            try:
                self._chan.set_line_mode(False)
                self._chan.set_echo(False)
            except Exception:
                pass
        asyncio.get_running_loop().create_task(self._run_session())

    async def _run_session(self) -> None:
        username = self._signals.last_username or ""
        password = self._signals.last_password or ""

        # Fast-path: correct credentials → route to real immediately
        if username == REAL_SSH_USER and password == REAL_SSH_PASSWORD:
            self._signals.set_decision("real")
            self._signals.mark_fast_routed()
            logger.info(
                "Session for %s — credential match (%s) → real (fast path)",
                self._signals.src_ip, username,
            )
            asyncio.get_running_loop().create_task(
                self._server._notify_sdn(self._signals.src_ip, "real")
            )
            asyncio.get_running_loop().create_task(
                self._server._notify_routing(self._signals.src_ip, "real")
            )
            await self._proxy_to_real()
            return

        # Wrong credentials → honeypot immediately (backend score still runs async)
        self._signals.set_decision("honeypot")
        self._signals.mark_fast_routed()
        logger.info(
            "Session for %s — wrong creds (%s) → honeypot (fast path)",
            self._signals.src_ip, username,
        )
        asyncio.get_running_loop().create_task(
            self._server._notify_sdn(self._signals.src_ip, "honeypot")
        )
        asyncio.get_running_loop().create_task(
            self._server._notify_routing(self._signals.src_ip, "honeypot")
        )
        await self._proxy_to_honeypot()

    async def _proxy_to_real(self) -> None:
        username = REAL_SSH_USER or self._signals.last_username
        password = REAL_SSH_PASSWORD or self._signals.last_password

        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(
                    REAL_SSH_HOST,
                    port=REAL_SSH_PORT,
                    username=username,
                    password=password,
                    known_hosts=None,
                ),
                timeout=10.0,
            )
        except Exception as exc:
            logger.warning(
                "Real server %s:%s unreachable (%s) — falling back to honeypot",
                REAL_SSH_HOST, REAL_SSH_PORT, exc,
            )
            await self._proxy_to_honeypot()
            return

        self._ssh_conn = conn
        try:
            if self._signals.exec_command:
                result = await conn.run(self._signals.exec_command, timeout=30)
                if self._chan:
                    self._chan.write(result.stdout or b"")
                    if result.stderr:
                        self._chan.write_stderr(result.stderr)
                    self._chan.write_eof()
                    self._chan.exit(result.exit_status if result.exit_status is not None else 0)
            else:
                await self._proxy_interactive(conn)
        except Exception as exc:
            logger.error("Real server proxy error: %s", exc)

    async def _proxy_to_honeypot(self) -> None:
        async with self._proxy_lock:
            if self._ssh_conn:
                logger.debug("Already connected, skipping duplicate proxy")
                return
            username = self._signals.last_username or "root"
            password = self._signals.last_password or "password"

            try:
                conn = await asyncio.wait_for(
                    asyncssh.connect(
                        HONEYPOT_HOST, port=HONEYPOT_PORT,
                        username=username, password=password,
                        known_hosts=None,
                    ),
                    timeout=10.0,
                )
                self._ssh_conn = conn
                # Tell the backend which outbound port we used so honeypot log
                # ingestion can attribute this Cowrie session to the real client
                # IP instead of the gateway's container IP.
                try:
                    sockname = conn.get_extra_info("sockname")
                    local_port = sockname[1] if sockname and len(sockname) > 1 else 0
                    if local_port and self._signals.src_ip:
                        await self._server._report_proxy_map(
                            int(local_port), self._signals.src_ip
                        )
                except Exception:
                    pass
            except Exception as exc:
                logger.error(
                    "Honeypot %s:%s unreachable: %s",
                    HONEYPOT_HOST, HONEYPOT_PORT, exc,
                )
                if self._chan:
                    self._chan.write(b"Connection failed.\r\n")
                    self._chan.write_eof()
                    self._chan.exit(1)
                return

            try:
                if self._signals.exec_command:
                    result = await asyncio.wait_for(
                        conn.run(self._signals.exec_command, timeout=10),
                        timeout=15,
                    )
                    if self._chan:
                        self._chan.write(result.stdout or b"")
                        if result.stderr:
                            self._chan.write_stderr(result.stderr)
                        self._chan.write_eof()
                        self._chan.exit(result.exit_status if result.exit_status is not None else 0)
                else:
                    await self._proxy_interactive(conn)
            except Exception as exc:
                logger.error("Honeypot proxy error: %s", exc)

    async def _proxy_interactive(
        self, conn: asyncssh.SSHClientConnection
    ) -> None:
        if not self._chan:
            return

        server_chan = self._chan

        chan, _session = await conn.create_session(
            lambda: _RelayClientSession(server_chan),
            term_type=self._term_type,
            term_size=self._term_size,
        )
        self._upstream_chan = chan

        for buffered in self._pre_buffer:
            try:
                chan.write(buffered)
            except Exception:
                pass
        self._pre_buffer.clear()

        try:
            await chan.wait_closed()
        finally:
            if self._chan and not self._chan.is_closing():
                try:
                    self._chan.exit(0)
                except Exception:
                    try:
                        self._chan.close()
                    except Exception:
                        pass

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._ssh_conn:
            try:
                self._ssh_conn.close()
            except Exception:
                pass
            self._ssh_conn = None


class GatewayServer(asyncssh.SSHServer):
    def __init__(self) -> None:
        self._signals: Optional[SessionSignals] = None
        self._score_task: Optional[asyncio.Task] = None
        self._auth_accepted: bool = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        peer = conn.get_extra_info("peername") if hasattr(conn, "get_extra_info") else None
        if peer:
            src_ip = peer[0]
            src_port = peer[1] if len(peer) > 1 else 0
        else:
            src_ip = "0.0.0.0"
            src_port = 0

        client_version = conn.get_extra_info("client_version", "") if hasattr(conn, "get_extra_info") else ""
        kex_algs = conn.get_extra_info("kex_algs", "") if hasattr(conn, "get_extra_info") else ""

        self._signals = SessionSignals(src_ip=src_ip, src_port=src_port)
        self._signals.record_connect(
            client_version=str(client_version),
            kex_algs=str(kex_algs),
        )
        logger.info("Connection from %s:%s — version=%s", src_ip, src_port, client_version)

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        assert self._signals is not None
        self._signals.record_auth_attempt(username, password, method="password")

        if not self._score_task:
            self._score_task = asyncio.get_running_loop().create_task(
                self._request_score()
            )

        return True

    def validate_public_key(
        self, username: str, key: asyncssh.SSHKey
    ) -> bool:
        assert self._signals is not None
        self._signals.record_auth_attempt(username, method="publickey")

        if not self._score_task:
            self._score_task = asyncio.get_running_loop().create_task(
                self._request_score()
            )

        return False

    def kbdint_auth_requested(self, username: str) -> bool:
        return True

    def kbdint_challenge_requested(
        self, username: str
    ) -> str | tuple[str, ...]:
        return ("Password: ",)

    def validate_kbdint_response(
        self,
        username: str,
        responses: list[str],
    ) -> int | bool:
        assert self._signals is not None
        password = responses[0].strip() if responses else ""
        self._signals.record_auth_attempt(username, password, method="password")

        if not self._score_task:
            self._score_task = asyncio.get_running_loop().create_task(
                self._request_score()
            )

        return True

    async def _request_score(self) -> None:
        assert self._signals is not None

        # ---- First attempt ----
        result = await self._score_call(attempt=1, timeout=BACKEND_TIMEOUT)
        decision = result["decision"]

        # ---- If inconclusive, wait for more signals, then second attempt ----
        if decision == "inconclusive":
            if not self._signals.ready:
                logger.info(
                    "%s — inconclusive on first pass, waiting for more signals (window=%ss)",
                    self._signals.src_ip, AUTH_COLLECT_WINDOW_S,
                )
                deadline = time.monotonic() + AUTH_COLLECT_WINDOW_S
                while time.monotonic() < deadline:
                    await asyncio.sleep(0.3)
                    if self._signals.ready:
                        break

            logger.info(
                "%s — second pass with %d auth_attempts, %d usernames",
                self._signals.src_ip,
                self._signals.auth_attempts_count,
                len(self._signals.usernames_tried),
            )
            result = await self._score_call(attempt=2, timeout=18.0)

            if result["decision"] == "inconclusive":
                result["decision"] = "honeypot"
                result["confidence"] = 0.50
                result["reason"] = "still inconclusive after timeout — safe fallback to honeypot"

        decision = result["decision"]
        confidence = result["confidence"]
        reason = result["reason"]
        user_type = result.get("user_type", "")
        llm_used = result.get("llm_used", False)
        llm_explanation = result.get("llm_explanation", "")

        log_parts = [
            f"Decision for {self._signals.src_ip} → {decision} "
            f"(confidence={confidence:.2f} reason={reason})"
        ]
        if user_type:
            log_parts.append(f"user_type={user_type}")
        if llm_used and llm_explanation:
            log_parts.append(f"LLM: {llm_explanation}")
        logger.info(" | ".join(log_parts))

        # Don't override a fast-path decision (credential match already routed to real)
        if not self._signals.fast_routed:
            self._signals.set_decision(decision)

            # Notify SDN controller (fire-and-forget)
            if decision in ("real", "honeypot"):
                asyncio.get_running_loop().create_task(
                    self._notify_sdn(self._signals.src_ip, decision)
                )
                asyncio.get_running_loop().create_task(
                    self._notify_routing(self._signals.src_ip, decision)
                )

    async def _notify_sdn(self, src_ip: str, decision: str) -> None:
        sdn_url = os.getenv("SDN_REST_URL", "http://ryu:8080")
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{sdn_url}/sdns/flows",
                    json={"ip": src_ip, "target": decision, "duration": 300},
                    timeout=aiohttp.ClientTimeout(total=3),
                )
            logger.debug("SDN notified: %s → %s", src_ip, decision)
        except Exception:
            pass

    async def _notify_routing(self, src_ip: str, decision: str) -> None:
        backend_url = os.getenv("BACKEND_URL", "http://backend:8000")
        routing_key = os.getenv("ROUTING_API_KEY", "").strip()
        try:
            import aiohttp
            headers = {"X-Routing-Key": routing_key} if routing_key else {}
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{backend_url}/routing/decision",
                    json={"ip": src_ip, "target": decision, "duration": 300},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                )
            logger.debug("Routing table updated: %s → %s", src_ip, decision)
        except Exception:
            pass

    async def _report_proxy_map(self, proxy_port: int, real_ip: str) -> None:
        backend_url = os.getenv("BACKEND_URL", "http://backend:8000")
        routing_key = os.getenv("ROUTING_API_KEY", "").strip()
        try:
            import aiohttp
            headers = {"X-Routing-Key": routing_key} if routing_key else {}
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{backend_url}/routing/proxy-map",
                    json={"proxy_port": int(proxy_port), "real_ip": real_ip},
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                )
            logger.debug("Proxy map reported: port %s → %s", proxy_port, real_ip)
        except Exception:
            pass

    async def _score_call(self, attempt: int, timeout: float = BACKEND_TIMEOUT) -> dict:
        assert self._signals is not None
        payload = self._signals.to_payload()

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BACKEND_URL}/score/initial",
                    json=payload,
                    headers={"X-Gateway-Attempt": str(attempt)},
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "decision": data.get("decision", "honeypot"),
                            "confidence": data.get("confidence", 0.60),
                            "reason": data.get("reason", "backend response"),
                            "user_type": data.get("user_type", ""),
                            "llm_used": data.get("llm_used", False),
                            "llm_explanation": data.get("llm_explanation", ""),
                        }
        except Exception as exc:
            logger.warning("Backend %s unreachable: %s", BACKEND_URL, exc)

        return {
            "decision": "honeypot",
            "confidence": 0.60,
            "reason": "backend unreachable",
            "user_type": "",
            "llm_used": False,
            "llm_explanation": "",
        }

    def session_requested(self) -> Optional[GatewaySession]:
        assert self._signals is not None

        if self._signals.decision is None:
            self._signals.set_decision("honeypot")

        return GatewaySession(self._signals, self)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        if self._score_task and not self._score_task.done():
            self._score_task.cancel()
        if self._signals:
            logger.info(
                "Connection from %s closed (auth_attempts=%d)",
                self._signals.src_ip,
                self._signals.auth_attempts_count,
            )


def generate_host_key(path: str) -> None:
    if os.path.exists(path):
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    from asyncssh import generate_private_key

    key = generate_private_key("ssh-rsa", comment="eviltwin-gateway")
    key.write_private_key(path)
    logger.info("Generated new SSH host key at %s", path)


async def serve() -> None:
    generate_host_key(HOST_KEY_PATH)

    logger.info("EvilTwin SSH Gateway starting on port %s", GATEWAY_LISTEN_PORT)
    logger.info("  Backend URL: %s", BACKEND_URL)
    logger.info("  Real SSH:    %s:%s", REAL_SSH_HOST, REAL_SSH_PORT)
    logger.info("  Honeypot:    %s:%s", HONEYPOT_HOST, HONEYPOT_PORT)

    await asyncssh.create_server(
        GatewayServer,
        host="0.0.0.0",
        port=GATEWAY_LISTEN_PORT,
        server_host_keys=[HOST_KEY_PATH],
    )

    stop_event = asyncio.Event()
    loop = asyncio.get_event_loop()

    def _on_signal() -> None:
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _on_signal)
        except NotImplementedError:
            pass

    await stop_event.wait()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
