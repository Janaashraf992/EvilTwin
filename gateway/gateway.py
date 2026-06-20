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


class GatewaySession(asyncssh.SSHServerSession):
    def __init__(self, signals: SessionSignals, server: "GatewayServer"):
        self._signals = signals
        self._server = server
        self._chan: Optional[asyncssh.SSHServerChannel] = None
        self._ssh_conn: Optional[asyncssh.SSHClientConnection] = None
        self._proxy_lock = asyncio.Lock()

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan

    def pty_requested(
        self,
        term_type: str,
        term_size: tuple[int, int, int, int],
        term_modes: dict[int, int],
    ) -> bool:
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
        asyncio.get_running_loop().create_task(self._run_session())

    async def _run_session(self) -> None:
        if self._server._score_task and not self._server._score_task.done():
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._server._score_task),
                    timeout=AUTH_COLLECT_WINDOW_S + 3.0,
                )
            except (asyncio.TimeoutError, Exception):
                pass

        decision = self._signals.decision
        if decision is None:
            decision = "honeypot"

        logger.info(
            "Session started for %s — routing to %s",
            self._signals.src_ip,
            decision,
        )

        if decision == "real":
            await self._proxy_to_real()
        else:
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
            except Exception as exc:
                logger.error("Honeypot %s:%s unreachable: %s", HONEYPOT_HOST, HONEYPOT_PORT, exc)
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
        chan, _ = await conn.create_session(term_type="xterm-256color")
        await self._bidirectional_copy(chan)

    async def _bidirectional_copy(
        self, remote_chan: asyncssh.SSHChannel
    ) -> None:
        assert self._chan is not None

        async def client_to_remote() -> None:
            try:
                while True:
                    data = await remote_chan.read(4096)
                    if not data:
                        break
                    self._chan.write(data)
            except Exception:
                pass
            finally:
                self._chan.write_eof()

        async def remote_to_client() -> None:
            try:
                while True:
                    data = await remote_chan.read(4096)
                    if not data:
                        break
                    self._chan.write(data)
            except Exception:
                pass
            finally:
                if self._chan:
                    self._chan.write_eof()

        await asyncio.gather(
            asyncio.create_task(client_to_remote()),
            asyncio.create_task(remote_to_client()),
        )

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

        return True

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
        result = await self._score_call(attempt=1)
        decision = result["decision"]

        # ---- If inconclusive, wait for more signals, then second attempt ----
        if decision == "inconclusive":
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
            result = await self._score_call(attempt=2)

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

        log_parts = [f"Decision for {self._signals.src_ip} → {decision} (confidence={confidence:.2f} reason={reason})"]
        if user_type:
            log_parts.append(f"user_type={user_type}")
        if llm_used and llm_explanation:
            log_parts.append(f"LLM: {llm_explanation}")
        logger.info(" | ".join(log_parts))
        self._signals.set_decision(decision)

    async def _score_call(self, attempt: int) -> dict:
        assert self._signals is not None
        payload = self._signals.to_payload()

        try:
            import aiohttp

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{BACKEND_URL}/score/initial?attempt={attempt}",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=BACKEND_TIMEOUT),
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
