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


def _coerce_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            try:
                return datetime.fromtimestamp(float(stripped), tz=timezone.utc)
            except ValueError:
                normalized = stripped.replace("Z", "+00:00")
                parsed = datetime.fromisoformat(normalized)
                if parsed.tzinfo is None:
                    return parsed.replace(tzinfo=timezone.utc)
                return parsed.astimezone(timezone.utc)

    raise ValueError("Unsupported Cowrie timestamp")


def parse_cowrie_event(raw_event: dict[str, Any], honeypot_ip: str) -> LogIngestRequest | None:
    eventid = raw_event.get("eventid")
    src_ip = raw_event.get("src_ip")
    session = raw_event.get("session")
    timestamp = raw_event.get("timestamp")

    if not eventid or not src_ip or not session or timestamp is None:
        return None

    dst_port = int(raw_event.get("dst_port") or 22)
    protocol = str(raw_event.get("protocol") or ("telnet" if dst_port == 23 else "ssh"))

    payload = {
        "eventid": str(eventid),
        "src_ip": src_ip,
        "src_port": int(raw_event.get("src_port") or 0),
        "dst_ip": raw_event.get("dst_ip") or honeypot_ip,
        "dst_port": dst_port,
        "session": str(session),
        "protocol": protocol,
        "timestamp": _coerce_timestamp(timestamp),
        "message": raw_event.get("message"),
        "input": raw_event.get("input"),
        "username": raw_event.get("username"),
        "password": raw_event.get("password"),
    }
    return LogIngestRequest.model_validate(payload)


@asynccontextmanager
async def _default_db_factory() -> AsyncIterator[Any]:
    async with get_db_context() as db:
        yield db


async def process_cowrie_log_line(
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
        logger.warning("Skipping invalid Cowrie log line")
        return False

    payload = parse_cowrie_event(raw_event, honeypot_ip)
    if payload is None:
        return False

    async with db_factory() as db:
        await ingest_handler(payload, db, runtime_state)

    return True


async def watch_cowrie_log(
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
                    await process_cowrie_log_line(
                        line,
                        honeypot_ip=honeypot_ip,
                        db_factory=db_factory,
                        runtime_state=runtime_state,
                        ingest_handler=ingest_handler,
                    )
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Cowrie log watcher failed while processing %s", log_path)

        await asyncio.sleep(poll_interval_seconds)