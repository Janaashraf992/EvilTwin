import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from schemas import LogIngestResponse
from services.cowrie import parse_cowrie_event, process_cowrie_log_line


def test_parse_cowrie_event_accepts_epoch_timestamps_and_defaults():
    payload = parse_cowrie_event(
        {
            "eventid": "cowrie.command.input",
            "src_ip": "198.51.100.10",
            "src_port": 44444,
            "session": "cowrie-session-1",
            "timestamp": 1_711_061_200,
            "input": "whoami",
            "message": "root",
        },
        honeypot_ip="10.0.2.10",
    )

    assert payload is not None
    assert str(payload.src_ip) == "198.51.100.10"
    assert str(payload.dst_ip) == "10.0.2.10"
    assert payload.dst_port == 22
    assert payload.protocol == "ssh"
    assert payload.timestamp == datetime.fromtimestamp(1_711_061_200, tz=timezone.utc)


@pytest.mark.asyncio
async def test_process_cowrie_log_line_uses_ingest_handler():
    seen = {}

    @asynccontextmanager
    async def fake_db_factory():
        yield object()

    async def fake_ingest_handler(payload, db, runtime_state):
        seen["payload"] = payload
        seen["db"] = db
        seen["runtime_state"] = runtime_state
        return LogIngestResponse(session_id=uuid4(), threat_score=0.4, threat_level=2)

    processed = await process_cowrie_log_line(
        json.dumps(
            {
                "eventid": "cowrie.login.success",
                "src_ip": "203.0.113.20",
                "src_port": 40404,
                "dst_ip": "10.0.2.10",
                "dst_port": 22,
                "session": "cowrie-session-2",
                "protocol": "ssh",
                "timestamp": "2026-04-24T10:00:00Z",
                "username": "root",
                "password": "toor",
            }
        ),
        honeypot_ip="10.0.2.10",
        db_factory=fake_db_factory,
        runtime_state=object(),
        ingest_handler=fake_ingest_handler,
    )

    assert processed is True
    assert str(seen["payload"].src_ip) == "203.0.113.20"
    assert seen["payload"].eventid == "cowrie.login.success"


@pytest.mark.asyncio
async def test_process_cowrie_log_line_rejects_invalid_json():
    processed = await process_cowrie_log_line(
        "{not-json}",
        honeypot_ip="10.0.2.10",
    )

    assert processed is False