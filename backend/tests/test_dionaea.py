import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

import pytest

from schemas import LogIngestResponse
from services.dionaea import parse_dionaea_event, process_dionaea_log_line


def test_parse_dionaea_http_accept_event_uses_verified_shape():
    payloads = parse_dionaea_event(
        {
            "connection": {"protocol": "httpd", "transport": "tcp", "type": "accept"},
            "dst_ip": "172.19.0.4",
            "dst_port": 80,
            "src_hostname": "",
            "src_ip": "172.19.0.1",
            "src_port": 43806,
            "timestamp": "2026-04-24T17:40:28.163010",
        },
        honeypot_ip="10.0.2.10",
    )

    assert len(payloads) == 1
    payload = payloads[0]
    assert payload.eventid == "dionaea.connection.tcp.accept"
    assert payload.protocol == "http"
    assert payload.dst_port == 80
    assert payload.timestamp == datetime(2026, 4, 24, 17, 40, 28, 163010, tzinfo=timezone.utc)


def test_parse_dionaea_ftp_commands_emit_follow_up_ingest_events():
    payloads = parse_dionaea_event(
        {
            "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
            "dst_ip": "172.19.0.4",
            "dst_port": 21,
            "src_hostname": "",
            "src_ip": "172.19.0.1",
            "src_port": 53854,
            "timestamp": "2026-04-24T17:40:28.182213",
            "ftp": {"commands": [{"command": "USER", "arguments": ["anonymous"]}]},
        },
        honeypot_ip="10.0.2.10",
    )

    assert len(payloads) == 2
    assert payloads[0].eventid == "dionaea.connection.tcp.accept"
    assert payloads[1].eventid == "dionaea.modules.python.ftp.command"
    assert payloads[1].input == "USER anonymous"
    assert payloads[1].username == "anonymous"
    assert payloads[0].session == payloads[1].session


def test_parse_dionaea_ftp_credentials_emit_combined_follow_up_event():
    payloads = parse_dionaea_event(
        {
            "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
            "dst_ip": "172.19.0.4",
            "dst_port": 21,
            "src_hostname": "",
            "src_ip": "172.19.0.1",
            "src_port": 53854,
            "timestamp": "2026-04-24T17:40:28.182213",
            "ftp": {
                "commands": [
                    {"command": "USER", "arguments": ["anonymous"]},
                    {"command": "PASS", "arguments": ["demo@example.com"]},
                ]
            },
            "credentials": [{"username": "anonymous", "password": "demo@example.com"}],
        },
        honeypot_ip="10.0.2.10",
    )

    assert len(payloads) == 4
    assert payloads[1].eventid == "dionaea.modules.python.ftp.command"
    assert payloads[1].username is None
    assert payloads[2].eventid == "dionaea.modules.python.ftp.command"
    assert payloads[2].password is None
    assert payloads[3].eventid == "dionaea.modules.python.ftp.login"
    assert payloads[3].username == "anonymous"
    assert payloads[3].password == "demo@example.com"


@pytest.mark.asyncio
async def test_process_dionaea_log_line_uses_ingest_handler_for_each_payload():
    seen = []

    @asynccontextmanager
    async def fake_db_factory():
        yield object()

    async def fake_ingest_handler(payload, db, runtime_state):
        seen.append((payload, db, runtime_state))
        return LogIngestResponse(session_id=uuid4(), threat_score=0.7, threat_level=3)

    processed = await process_dionaea_log_line(
        json.dumps(
            {
                "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
                "dst_ip": "172.19.0.4",
                "dst_port": 21,
                "src_hostname": "",
                "src_ip": "172.19.0.1",
                "src_port": 53854,
                "timestamp": "2026-04-24T17:40:28.182213",
                "ftp": {"commands": [{"command": "PASS", "arguments": ["guest@example.com"]}]},
            }
        ),
        honeypot_ip="10.0.2.10",
        db_factory=fake_db_factory,
        runtime_state=object(),
        ingest_handler=fake_ingest_handler,
    )

    assert processed is True
    assert len(seen) == 2
    assert seen[0][0].eventid == "dionaea.connection.tcp.accept"
    assert seen[1][0].eventid == "dionaea.modules.python.ftp.command"
    assert seen[1][0].password == "guest@example.com"


@pytest.mark.asyncio
async def test_process_dionaea_log_line_emits_combined_credential_payload():
    seen = []

    @asynccontextmanager
    async def fake_db_factory():
        yield object()

    async def fake_ingest_handler(payload, db, runtime_state):
        seen.append(payload)
        return LogIngestResponse(session_id=uuid4(), threat_score=0.2, threat_level=1)

    processed = await process_dionaea_log_line(
        json.dumps(
            {
                "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
                "dst_ip": "172.19.0.4",
                "dst_port": 21,
                "src_hostname": "",
                "src_ip": "172.19.0.1",
                "src_port": 53854,
                "timestamp": "2026-04-24T17:40:28.182213",
                "ftp": {
                    "commands": [
                        {"command": "USER", "arguments": ["anonymous"]},
                        {"command": "PASS", "arguments": ["demo@example.com"]},
                    ]
                },
                "credentials": [{"username": "anonymous", "password": "demo@example.com"}],
            }
        ),
        honeypot_ip="10.0.2.10",
        db_factory=fake_db_factory,
        runtime_state=object(),
        ingest_handler=fake_ingest_handler,
    )

    assert processed is True
    assert [payload.eventid for payload in seen] == [
        "dionaea.connection.tcp.accept",
        "dionaea.modules.python.ftp.command",
        "dionaea.modules.python.ftp.command",
        "dionaea.modules.python.ftp.login",
    ]
    assert seen[-1].username == "anonymous"
    assert seen[-1].password == "demo@example.com"


@pytest.mark.asyncio
async def test_process_dionaea_log_line_rejects_invalid_json():
    processed = await process_dionaea_log_line(
        "{not-json}",
        honeypot_ip="10.0.2.10",
    )

    assert processed is False