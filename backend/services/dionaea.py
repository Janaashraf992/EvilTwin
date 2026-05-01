from __future__ import annotations

import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable

from database import get_db_context
from schemas import LogIngestRequest, LogIngestResponse
from services.ingest import ingest_event
from state import AppState, app_state

logger = logging.getLogger(__name__)

DbFactory = Callable[[], AsyncIterator[Any]]
IngestHandler = Callable[[LogIngestRequest, Any, AppState], Awaitable[LogIngestResponse]]

_PROTOCOL_ALIASES = {
    "ftpd": "ftp",
    "httpd": "http",
    "mqttd": "mqtt",
    "mssqld": "mssql",
    "mysqld": "mysql",
    "smbd": "smb",
    "tftpd": "tftp",
}

_INCIDENT_CONNECTION_MESSAGES = {
    "accept": "accepted",
    "connect": "initiated",
    "free": "closed",
    "listen": "listened for",
    "reject": "rejected",
}


def _coerce_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        normalized = value.strip().replace("Z", "+00:00")
        if normalized:
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

    raise ValueError("Unsupported Dionaea timestamp")


def _normalize_protocol(value: Any, dst_port: int) -> str:
    if isinstance(value, str) and value.strip():
        protocol = value.strip().lower()
        return _PROTOCOL_ALIASES.get(protocol, protocol)

    return {
        21: "ftp",
        80: "http",
        1433: "mssql",
        445: "smb",
    }.get(dst_port, "tcp")


def _build_session(raw_event: dict[str, Any], protocol: str, timestamp: datetime) -> str:
    connection = raw_event.get("connection") or {}
    connection_id = connection.get("id") or raw_event.get("id") or raw_event.get("attack_id")
    if connection_id is not None:
        return f"dionaea-{protocol}-{connection_id}"

    src_ip = raw_event.get("src_ip") or "unknown"
    src_port = int(raw_event.get("src_port") or 0)
    dst_ip = raw_event.get("dst_ip") or "unknown"
    dst_port = int(raw_event.get("dst_port") or 0)
    return f"dionaea-{protocol}-{src_ip}-{src_port}-{dst_ip}-{dst_port}-{timestamp.isoformat()}"


def _base_payload(raw_event: dict[str, Any], honeypot_ip: str) -> dict[str, Any] | None:
    timestamp_value = raw_event.get("timestamp")
    src_ip = raw_event.get("src_ip")
    if src_ip is None or timestamp_value is None:
        return None

    dst_port = int(raw_event.get("dst_port") or 0)
    connection = raw_event.get("connection") or {}
    protocol = _normalize_protocol(connection.get("protocol"), dst_port)
    timestamp = _coerce_timestamp(timestamp_value)
    session = _build_session(
        {
            **raw_event,
            "dst_ip": raw_event.get("dst_ip") or honeypot_ip,
            "dst_port": dst_port,
        },
        protocol,
        timestamp,
    )

    return {
        "src_ip": src_ip,
        "src_port": int(raw_event.get("src_port") or 0),
        "dst_ip": raw_event.get("dst_ip") or honeypot_ip,
        "dst_port": dst_port,
        "session": session,
        "protocol": protocol,
        "timestamp": timestamp,
    }


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None

    text = str(value).strip()
    return text or None


def _stringify_annotation_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        rendered = ", ".join(str(item) for item in value if item is not None)
        return rendered or None
    if isinstance(value, dict):
        rendered = ", ".join(
            f"{key}={item}" for key, item in value.items() if item is not None and str(item).strip()
        )
        return rendered or None

    return _optional_text(value)


def _annotation_summary(data: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    parts: list[str] = []
    for key in keys:
        value = _stringify_annotation_value(data.get(key))
        if value is None:
            continue
        parts.append(f"{key}={value}")

    if not parts:
        return None
    return "; ".join(parts)


def _build_payload(
    base_payload: dict[str, Any],
    eventid: str,
    *,
    message: str | None = None,
    input_text: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> LogIngestRequest:
    payload = {
        **base_payload,
        "eventid": eventid,
    }
    if message is not None:
        payload["message"] = message
    if input_text is not None:
        payload["input"] = input_text
    if username is not None:
        payload["username"] = username
    if password is not None:
        payload["password"] = password

    return LogIngestRequest.model_validate(payload)


def _incident_base_payload(
    raw_event: dict[str, Any], honeypot_ip: str
) -> tuple[dict[str, Any], str, dict[str, Any]] | None:
    origin = _optional_text(raw_event.get("origin"))
    incident_data = raw_event.get("data")
    if origin is None or not isinstance(incident_data, dict):
        return None

    connection = incident_data.get("connection")
    if not isinstance(connection, dict):
        return None

    timestamp_value = raw_event.get("timestamp")
    if timestamp_value is None:
        return None

    dst_port = int(connection.get("local_port") or 0)
    protocol = _normalize_protocol(connection.get("protocol"), dst_port)
    timestamp = _coerce_timestamp(timestamp_value)
    dst_ip = connection.get("local_ip") or honeypot_ip
    src_ip = connection.get("remote_ip")
    if src_ip is None:
        return None

    session = _build_session(
        {
            "connection": {"id": connection.get("id")},
            "id": connection.get("id"),
            "src_ip": src_ip,
            "src_port": int(connection.get("remote_port") or 0),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
        },
        protocol,
        timestamp,
    )

    return (
        {
            "src_ip": src_ip,
            "src_port": int(connection.get("remote_port") or 0),
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "session": session,
            "protocol": protocol,
            "timestamp": timestamp,
        },
        origin,
        incident_data,
    )


def _parse_incident_event(raw_event: dict[str, Any], honeypot_ip: str) -> list[LogIngestRequest]:
    incident_payload = _incident_base_payload(raw_event, honeypot_ip)
    if incident_payload is None:
        return []

    base_payload, origin, incident_data = incident_payload
    protocol = str(base_payload["protocol"])

    if origin.startswith("dionaea.connection."):
        connection_type = origin.rsplit(".", 1)[-1]
        verb = _INCIDENT_CONNECTION_MESSAGES.get(connection_type, "observed")
        return [
            _build_payload(
                base_payload,
                origin,
                message=f"Dionaea {verb} a {protocol} connection on port {base_payload['dst_port']}",
            )
        ]

    if origin == "dionaea.modules.python.ftp.command":
        command = _optional_text(incident_data.get("command"))
        arguments = [
            str(argument)
            for argument in (incident_data.get("arguments") or [])
            if argument is not None and str(argument).strip()
        ]
        if command is None:
            return []

        input_text = " ".join([command, *arguments]).strip()
        upper_command = command.upper()
        username = arguments[0] if upper_command == "USER" and arguments else None
        password = arguments[0] if upper_command == "PASS" and arguments else None
        return [
            _build_payload(
                base_payload,
                origin,
                message="FTP command observed by Dionaea",
                input_text=input_text,
                username=username,
                password=password,
            )
        ]

    if origin.endswith(".login") and origin.startswith("dionaea.modules.python."):
        username = _optional_text(incident_data.get("username"))
        password = _optional_text(incident_data.get("password"))
        detail_keys = {
            "ftp": (),
            "mssql": ("hostname", "appname", "cltintname", "database", "language"),
            "http": ("method", "path", "url", "user_agent"),
            "smb": ("hostname",),
        }.get(protocol, ())
        detail_summary = _annotation_summary(incident_data, detail_keys)
        message = f"{protocol.upper()} credential attempt observed by Dionaea"
        if detail_summary is not None:
            message = f"{message} ({detail_summary})"

        return [
            _build_payload(
                base_payload,
                origin,
                message=message,
                username=username,
                password=password,
            )
        ]

    if origin == "dionaea.modules.python.mssql.cmd":
        command = _optional_text(incident_data.get("cmd"))
        status = _optional_text(incident_data.get("status"))
        message = "MSSQL query observed by Dionaea"
        if status is not None:
            message = f"{message} (status={status})"
        return [
            _build_payload(
                base_payload,
                origin,
                message=message,
                input_text=command,
            )
        ]

    if origin == "dionaea.modules.python.smb.dcerpc.bind":
        uuid = _optional_text(incident_data.get("uuid"))
        transfer_syntax = _optional_text(
            incident_data.get("transfer_syntax") or incident_data.get("transfersyntax")
        )
        message = "SMB DCERPC bind observed by Dionaea"
        if transfer_syntax is not None:
            message = f"{message} (transfer_syntax={transfer_syntax})"
        input_text = " ".join(part for part in ["DCERPC bind", uuid] if part).strip() or None
        return [
            _build_payload(
                base_payload,
                origin,
                message=message,
                input_text=input_text,
            )
        ]

    if origin == "dionaea.modules.python.smb.dcerpc.request":
        uuid = _optional_text(incident_data.get("uuid"))
        opnum = incident_data.get("opnum")
        input_parts = ["DCERPC request"]
        if uuid is not None:
            input_parts.append(uuid)
        if opnum is not None:
            input_parts.append(f"opnum {opnum}")
        return [
            _build_payload(
                base_payload,
                origin,
                message="SMB DCERPC request observed by Dionaea",
                input_text=" ".join(input_parts),
            )
        ]

    if protocol == "http" and any(
        incident_data.get(key) is not None for key in ("method", "path", "url", "user_agent")
    ):
        method = _optional_text(incident_data.get("method"))
        target = _optional_text(incident_data.get("path") or incident_data.get("url"))
        detail_summary = _annotation_summary(incident_data, ("user_agent", "host"))
        message = "HTTP request metadata observed by Dionaea"
        if detail_summary is not None:
            message = f"{message} ({detail_summary})"
        input_text = " ".join(part for part in [method, target] if part).strip() or None
        return [
            _build_payload(
                base_payload,
                origin,
                message=message,
                input_text=input_text,
            )
        ]

    detail_keys = tuple(key for key in incident_data.keys() if key != "connection")
    detail_summary = _annotation_summary(incident_data, detail_keys)
    message = f"Dionaea {protocol} incident observed"
    if detail_summary is not None:
        message = f"{message} ({detail_summary})"

    return [_build_payload(base_payload, origin, message=message)]


def _parse_ftp_command_events(base_payload: dict[str, Any], raw_event: dict[str, Any]) -> list[LogIngestRequest]:
    ftp_data = raw_event.get("ftp")
    if not isinstance(ftp_data, dict):
        return []

    commands = ftp_data.get("commands")
    if not isinstance(commands, list):
        return []

    has_explicit_credentials = any(
        isinstance(entry, dict)
        and ((entry.get("username") is not None) or (entry.get("password") is not None))
        for entry in (raw_event.get("credentials") or [])
    )

    payloads: list[LogIngestRequest] = []
    for command_entry in commands:
        if not isinstance(command_entry, dict):
            continue

        command = str(command_entry.get("command") or "").strip()
        arguments = [str(arg) for arg in (command_entry.get("arguments") or []) if arg is not None]
        if not command:
            continue

        input_text = " ".join([command, *arguments]).strip()
        upper_command = command.upper()
        username = (
            arguments[0]
            if (not has_explicit_credentials and upper_command == "USER" and arguments)
            else None
        )
        password = (
            arguments[0]
            if (not has_explicit_credentials and upper_command == "PASS" and arguments)
            else None
        )

        payloads.append(
            _build_payload(
                base_payload,
                "dionaea.modules.python.ftp.command",
                message="FTP command observed by Dionaea",
                input_text=input_text,
                username=username,
                password=password,
            )
        )

    return payloads


def _parse_credential_events(base_payload: dict[str, Any], raw_event: dict[str, Any]) -> list[LogIngestRequest]:
    credentials = raw_event.get("credentials")
    if not isinstance(credentials, list):
        return []

    protocol = str(base_payload["protocol"])
    payloads: list[LogIngestRequest] = []
    for credential_entry in credentials:
        if not isinstance(credential_entry, dict):
            continue

        username_value = credential_entry.get("username")
        password_value = credential_entry.get("password")
        username = str(username_value).strip() if username_value is not None else None
        password = str(password_value).strip() if password_value is not None else None

        if not username and not password:
            continue

        payloads.append(
            _build_payload(
                base_payload,
                f"dionaea.modules.python.{protocol}.login",
                message=f"{protocol.upper()} credential attempt observed by Dionaea",
                username=username or None,
                password=password or None,
            )
        )

    return payloads


def parse_dionaea_event(raw_event: dict[str, Any], honeypot_ip: str) -> list[LogIngestRequest]:
    incident_payloads = _parse_incident_event(raw_event, honeypot_ip)
    if incident_payloads:
        return incident_payloads

    base_payload = _base_payload(raw_event, honeypot_ip)
    if base_payload is None:
        return []

    connection = raw_event.get("connection") or {}
    transport = str(connection.get("transport") or "tcp").lower()
    connection_type = str(connection.get("type") or "accept").lower()
    protocol = base_payload["protocol"]

    payloads = [
        _build_payload(
            base_payload,
            f"dionaea.connection.{transport}.{connection_type}",
            message=f"Dionaea accepted a {protocol} connection on port {base_payload['dst_port']}",
        )
    ]
    payloads.extend(_parse_ftp_command_events(base_payload, raw_event))
    payloads.extend(_parse_credential_events(base_payload, raw_event))
    return payloads


@asynccontextmanager
async def _default_db_factory() -> AsyncIterator[Any]:
    async with get_db_context() as db:
        yield db


async def process_dionaea_log_line(
    line: str,
    *,
    honeypot_ip: str,
    db_factory: DbFactory = _default_db_factory,
    runtime_state: AppState = app_state,
    ingest_handler: IngestHandler = ingest_event,
) -> bool:
    try:
        raw_event = json.loads(line)
    except json.JSONDecodeError:
        logger.warning("Skipping invalid Dionaea log line")
        return False

    payloads = parse_dionaea_event(raw_event, honeypot_ip)
    if not payloads:
        return False

    async with db_factory() as db:
        for payload in payloads:
            await ingest_handler(payload, db, runtime_state)
            flush = getattr(db, "flush", None)
            if callable(flush):
                await flush()

    return True


async def watch_dionaea_log(
    log_path: str,
    honeypot_ip: str,
    *,
    poll_interval_seconds: float,
    db_factory: DbFactory = _default_db_factory,
    runtime_state: AppState = app_state,
    ingest_handler: IngestHandler = ingest_event,
) -> None:
    path = Path(log_path)
    offset: int | None = None

    while True:
        try:
            if not path.exists():
                await asyncio.sleep(poll_interval_seconds)
                continue

            current_size = path.stat().st_size
            with path.open("r", encoding="utf-8") as handle:
                if offset is None:
                    handle.seek(0, os.SEEK_END)
                    offset = handle.tell()
                elif current_size < offset:
                    offset = 0
                    handle.seek(0)
                else:
                    handle.seek(offset)

                while True:
                    line = handle.readline()
                    if not line:
                        offset = handle.tell()
                        break
                    offset = handle.tell()
                    await process_dionaea_log_line(
                        line,
                        honeypot_ip=honeypot_ip,
                        db_factory=db_factory,
                        runtime_state=runtime_state,
                        ingest_handler=ingest_handler,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Dionaea log watcher failed while processing %s", log_path)

        await asyncio.sleep(poll_interval_seconds)