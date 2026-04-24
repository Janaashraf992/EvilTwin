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


def _parse_ftp_command_events(base_payload: dict[str, Any], raw_event: dict[str, Any]) -> list[LogIngestRequest]:
    ftp_data = raw_event.get("ftp")
    if not isinstance(ftp_data, dict):
        return []

    commands = ftp_data.get("commands")
    if not isinstance(commands, list):
        return []

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
        username = arguments[0] if upper_command == "USER" and arguments else None
        password = arguments[0] if upper_command == "PASS" and arguments else None

        payloads.append(
            LogIngestRequest.model_validate(
                {
                    **base_payload,
                    "eventid": "dionaea.modules.python.ftp.command",
                    "message": "FTP command observed by Dionaea",
                    "input": input_text,
                    "username": username,
                    "password": password,
                }
            )
        )

    return payloads


def parse_dionaea_event(raw_event: dict[str, Any], honeypot_ip: str) -> list[LogIngestRequest]:
    base_payload = _base_payload(raw_event, honeypot_ip)
    if base_payload is None:
        return []

    connection = raw_event.get("connection") or {}
    transport = str(connection.get("transport") or "tcp").lower()
    connection_type = str(connection.get("type") or "accept").lower()
    protocol = base_payload["protocol"]

    payloads = [
        LogIngestRequest.model_validate(
            {
                **base_payload,
                "eventid": f"dionaea.connection.{transport}.{connection_type}",
                "message": f"Dionaea accepted a {protocol} connection on port {base_payload['dst_port']}",
            }
        )
    ]
    payloads.extend(_parse_ftp_command_events(base_payload, raw_event))
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