"""
Dummy Real SSH Server — shows legitimate Ubuntu banner for "real" decisions.
Gateway proxies SSH here when the decision is "real".
"""
from __future__ import annotations

import asyncio
import logging
import os

import asyncssh

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DUMMY-REAL] %(message)s")
logger = logging.getLogger("dummy-real")

SSH_USER = os.getenv("REAL_SSH_USER", "gateway")
SSH_PASSWORD = os.getenv("REAL_SSH_PASSWORD", "gateway")
LISTEN_PORT = int(os.getenv("LISTEN_PORT", "22"))
PORTAL_URL = os.getenv("REAL_PORTAL_URL", "http://192.168.1.35:8888")

BANNER = (
    "Welcome to Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/advantage\r\n"
    "\r\n"
    "  System load:  0.08               Processes: 187\r\n"
    "  Usage of /:   23.4% of 98.30GB   Users logged in: 1\r\n"
    "  Memory usage: 12%                IPv4 address for eth0: 10.0.1.100\r\n"
    "  Swap usage:   0%\r\n"
    "\r\n"
    "You are authenticated as a legitimate user.\r\n"
    "Last login: Thu Jun 19 14:35:01 2026 from 10.0.1.10\r\n"
)

MOTD = (
    "\r\n"
    "  \033[1;32mWelcome to the Real Network\033[0m\r\n"
    "  You have been verified as a normal user.\r\n"
    "  No security alerts have been triggered.\r\n"
    f"  Authenticated web portal: \033[1;36m{PORTAL_URL}\033[0m\r\n"
    "  (type 'portal' for the link, 'help' for commands, 'exit' to quit)\r\n"
    "\r\n"
)

COMMANDS = {
    "whoami": "real",
    "id": "uid=1000(real) gid=1000(real) groups=1000(real)",
    "pwd": "/home/real",
    "ls": "",
    "hostname": "real-server",
    "uname": "Linux",
    "uname -a": "Linux real-server 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
}


class RealServerSession(asyncssh.SSHServerSession):
    def __init__(self, *args, **kw) -> None:
        super().__init__()
        self._chan: asyncssh.SSHServerChannel | None = None
        self._line = ""
        self._greeted = False

    def connection_made(self, chan: asyncssh.SSHServerChannel) -> None:
        self._chan = chan

    def shell_requested(self) -> bool:
        return True

    def pty_requested(self, term_type, term_size, term_modes) -> bool:
        return True

    def session_started(self) -> None:
        try:
            self._chan.set_line_mode(False)
            self._chan.set_echo(False)
        except Exception:
            pass
        asyncio.ensure_future(self._greet())

    async def _greet(self) -> None:
        await asyncio.sleep(0.15)
        if self._greeted or self._chan is None or self._chan.is_closing():
            return
        self._greeted = True
        self._chan.write(BANNER)
        self._chan.write(MOTD)
        self._prompt()

    def data_received(self, data, datatype) -> None:
        if not self._greeted:
            return
        for ch in data:
            if ch in ("\r", "\n"):
                self._chan.write("\r\n")
                if self._run_command(self._line.strip()):
                    return
                self._line = ""
                self._prompt()
            elif ch in ("\x7f", "\x08"):
                if self._line:
                    self._line = self._line[:-1]
                    self._chan.write("\b \b")
            elif ch == "\x03":
                self._line = ""
                self._chan.write("^C\r\n")
                self._prompt()
            elif ch == "\x04":
                self._chan.write("logout\r\n")
                self._chan.exit(0)
                return
            elif ch.isprintable():
                self._line += ch
                self._chan.write(ch)

    def _run_command(self, cmd: str) -> bool:
        if not cmd:
            return False
        if cmd in ("exit", "logout", "quit"):
            self._chan.write("logout\r\n")
            self._chan.exit(0)
            return True
        if cmd in ("portal", "url"):
            self._chan.write(f"Authenticated web portal: {PORTAL_URL}\r\n")
            return False
        if cmd == "help":
            self._chan.write(
                "You are authenticated as a legitimate user.\r\n"
                f"Access the web portal at: {PORTAL_URL}\r\n"
                "Available: whoami id pwd ls hostname uname portal exit\r\n"
            )
            return False
        out = COMMANDS.get(cmd)
        if out is None:
            prog = cmd.split()[0]
            out = COMMANDS.get(prog, f"-bash: {prog}: command not found")
        if out:
            self._chan.write(out + "\r\n")
        return False

    def _prompt(self) -> None:
        self._chan.write("user@real-server:~$ ")


class RealServer(asyncssh.SSHServer):
    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == SSH_USER and password == SSH_PASSWORD

    def session_requested(self) -> RealServerSession:
        return RealServerSession()


async def serve() -> None:
    host_key_path = "/tmp/ssh_host_rsa_key_real"
    if not os.path.exists(host_key_path):
        from asyncssh import generate_private_key
        key = generate_private_key("ssh-rsa", comment="dummy-real")
        key.write_private_key(host_key_path)

    logger.info("Dummy Real SSH Server starting on port %s", LISTEN_PORT)
    logger.info("  Auth: %s / %s", SSH_USER, SSH_PASSWORD)
    logger.info("  Portal: %s", PORTAL_URL)

    await asyncssh.create_server(
        RealServer,
        host="0.0.0.0",
        port=LISTEN_PORT,
        server_host_keys=[host_key_path],
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (__import__("signal").SIGINT, __import__("signal").SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
