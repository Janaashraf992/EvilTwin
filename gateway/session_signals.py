from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SessionSignals:
    src_ip: str
    src_port: int
    client_version: str = ""
    kex_algorithms_hash: str = ""
    time_to_first_auth: float = 0.0
    auth_attempts_count: int = 0
    auth_methods_used: list[str] = field(default_factory=list)
    usernames_tried: list[str] = field(default_factory=list)
    passwords_tried: list[str] = field(default_factory=list)
    public_key_attempted: bool = False
    shell_requested: bool = False
    exec_command: Optional[str] = None
    is_interactive: bool = False
    auth_attempt_interval: float = 0.0

    _connect_time: float = field(default_factory=time.monotonic, init=False)
    _first_auth_time: Optional[float] = field(default=None, init=False)
    _last_auth_time: float = field(default_factory=time.monotonic, init=False)
    _decision_made: bool = field(default=False, init=False)
    _decision: Optional[str] = field(default=None, init=False)
    _fast_routed: bool = field(default=False, init=False)

    def record_connect(self, client_version: str, kex_algs: str) -> None:
        self._connect_time = time.monotonic()
        self.client_version = client_version
        self.kex_algorithms_hash = hashlib.md5(
            kex_algs.encode()
        ).hexdigest()[:12]

    def record_auth_attempt(
        self,
        username: str,
        password: str = "",
        method: str = "password",
    ) -> None:
        now = time.monotonic()
        if self._first_auth_time is None:
            self._first_auth_time = now
            self.time_to_first_auth = round(now - self._connect_time, 3)

        self.auth_attempts_count += 1
        if method not in self.auth_methods_used:
            self.auth_methods_used.append(method)
        if username and username not in self.usernames_tried:
            self.usernames_tried.append(username)
        if password:
            self.passwords_tried.append(password)
        if method == "publickey":
            self.public_key_attempted = True

        if self.auth_attempts_count >= 2 and self._last_auth_time:
            interval = now - self._last_auth_time
            self.auth_attempt_interval = round(interval, 3)

        self._last_auth_time = now

    def record_session_request(self, term: str = "", command: str = "") -> None:
        if command:
            self.exec_command = command
            self.is_interactive = False
        else:
            self.shell_requested = True
            self.is_interactive = True

    @property
    def ready(self) -> bool:
        if self._decision_made:
            return True
        if self.auth_attempts_count >= 3:
            return True
        if self.shell_requested or self.exec_command:
            return True
        elapsed = time.monotonic() - self._connect_time
        if elapsed > 5.0:
            return True
        return False

    @property
    def last_username(self) -> str:
        if self.usernames_tried:
            return self.usernames_tried[-1]
        return ""

    @property
    def last_password(self) -> str:
        if self.passwords_tried:
            return self.passwords_tried[-1]
        return ""

    def set_decision(self, decision: str) -> None:
        self._decision = decision
        self._decision_made = True

    @property
    def decision(self) -> Optional[str]:
        return self._decision

    @property
    def fast_routed(self) -> bool:
        return self._fast_routed

    def mark_fast_routed(self) -> None:
        self._fast_routed = True

    def to_payload(self) -> dict:
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "client_version": self.client_version,
            "kex_algorithms_hash": self.kex_algorithms_hash,
            "time_to_first_auth": self.time_to_first_auth,
            "auth_attempts_count": self.auth_attempts_count,
            "auth_methods_used": self.auth_methods_used,
            "usernames_tried": self.usernames_tried,
            "passwords_tried": self.passwords_tried,
            "public_key_attempted": self.public_key_attempted,
            "shell_requested": self.shell_requested,
            "exec_command": self.exec_command,
            "is_interactive": self.is_interactive,
            "auth_attempt_interval": self.auth_attempt_interval,
        }
