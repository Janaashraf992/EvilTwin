import uuid
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import pytest

from models import AttackerProfile, SessionLog
from services.dionaea import process_dionaea_log_line


@pytest.mark.asyncio
async def test_health_endpoint(integration_client):
    response = await integration_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["database"] is True
    assert "uptime" in data


@pytest.mark.asyncio
async def test_log_and_sessions_and_score_endpoints(integration_client):
    payload = {
        "eventid": "cowrie.command.input",
        "src_ip": "203.0.113.10",
        "src_port": 50555,
        "dst_ip": "10.0.2.10",
        "dst_port": 22,
        "session": "sess-001",
        "protocol": "ssh",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "cmd executed",
        "input": "whoami",
        "username": "root",
        "password": "toor"
    }

    ingest_response = await integration_client.post("/log", json=payload)
    assert ingest_response.status_code == 200
    ingest_data = ingest_response.json()
    assert "session_id" in ingest_data
    assert ingest_data["threat_level"] == 0

    sessions_response = await integration_client.get("/sessions", params={"page": 1, "page_size": 25})
    assert sessions_response.status_code == 200
    sessions_data = sessions_response.json()
    assert sessions_data["total"] >= 1
    assert len(sessions_data["items"]) >= 1

    session_id = ingest_data["session_id"]
    detail_response = await integration_client.get(f"/sessions/{session_id}")
    assert detail_response.status_code == 200
    detail_data = detail_response.json()
    assert detail_data["id"] == session_id
    assert detail_data["attacker_ip"] == "203.0.113.10"

    score_response = await integration_client.get("/score/203.0.113.10")
    assert score_response.status_code == 200
    score_data = score_response.json()
    assert score_data["ip"] == "203.0.113.10"
    assert 0 <= score_data["threat_level"] <= 4


@pytest.mark.asyncio
async def test_sessions_detail_not_found(integration_client):
    missing_id = str(uuid.uuid4())
    response = await integration_client.get(f"/sessions/{missing_id}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_me_endpoint_accepts_local_demo_domain(integration_client):
    response = await integration_client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "integration@eviltwin.local"


@pytest.mark.asyncio
async def test_sessions_include_geo_fields(integration_client, integration_db_session):
    profile = AttackerProfile(
        ip="203.0.113.222",
        country="US",
        city="Seattle",
        isp="Example ISP",
        latitude=47.6062,
        longitude=-122.3321,
        threat_score=0.7,
        threat_level=3,
        vpn_detected=True,
    )
    session = SessionLog(
        id=uuid.uuid4(),
        attacker_ip="203.0.113.222",
        honeypot="cowrie",
        protocol="ssh",
        start_time=datetime.now(timezone.utc).replace(tzinfo=None),
        end_time=datetime.now(timezone.utc).replace(tzinfo=None),
        commands=[],
        credentials_tried=[],
        malware_hashes=[],
        raw_log={"events": []},
    )
    integration_db_session.add(profile)
    integration_db_session.add(session)
    await integration_db_session.commit()

    response = await integration_client.get("/sessions", params={"ip": "203.0.113.222"})
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["latitude"] == pytest.approx(47.6062)
    assert item["longitude"] == pytest.approx(-122.3321)


@pytest.mark.asyncio
async def test_dionaea_ftp_event_creates_single_session_with_commands(
    integration_client,
    integration_db_session,
):
    @asynccontextmanager
    async def fake_db_factory():
        yield integration_db_session

    processed = await process_dionaea_log_line(
        json.dumps(
            {
                "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
                "dst_ip": "172.21.0.2",
                "dst_port": 21,
                "src_hostname": "",
                "src_ip": "172.21.0.1",
                "src_port": 37370,
                "timestamp": "2026-04-24T17:56:39.389701",
                "ftp": {
                    "commands": [
                        {"command": "USER", "arguments": ["anonymous"]},
                        {"command": "PASS", "arguments": ["demo@example.com"]},
                        {"command": "QUIT", "arguments": []},
                    ]
                },
                "credentials": [{"username": "anonymous", "password": "demo@example.com"}],
            }
        ),
        honeypot_ip="10.0.2.10",
        db_factory=fake_db_factory,
    )

    assert processed is True
    await integration_db_session.commit()

    response = await integration_client.get(
        "/sessions",
        params={"page": 1, "page_size": 10, "honeypot": "dionaea", "ip": "172.21.0.1"},
    )
    assert response.status_code == 200

    items = response.json()["items"]
    assert len(items) == 1

    session = items[0]
    assert session["honeypot"] == "dionaea"
    assert session["protocol"] == "ftp"
    assert [entry["command"] for entry in session["commands"]] == [
        "USER anonymous",
        "PASS demo@example.com",
        "QUIT",
    ]
    assert session["credentials_tried"] == [
        {"username": "anonymous", "password": "demo@example.com", "success": False},
    ]


@pytest.mark.asyncio
async def test_dionaea_mssql_incidents_create_single_session_with_annotations(
    integration_client,
    integration_db_session,
):
    @asynccontextmanager
    async def fake_db_factory():
        yield integration_db_session

    login_line = json.dumps(
        {
            "name": "dionaea",
            "origin": "dionaea.modules.python.mssql.login",
            "timestamp": "2026-04-24T18:12:10.000000",
            "data": {
                "connection": {
                    "id": "mssql-conn-1",
                    "local_ip": "10.0.2.10",
                    "local_port": 1433,
                    "remote_ip": "172.21.0.11",
                    "remote_port": 40211,
                    "remote_hostname": "",
                    "protocol": "mssqld",
                    "transport": "tcp",
                },
                "username": "sa",
                "password": "P@ssw0rd!",
                "hostname": "kali-box",
                "appname": "sqlcmd",
                "cltintname": "ODBC Driver 18",
                "database": "master",
            },
        }
    )
    command_line = json.dumps(
        {
            "name": "dionaea",
            "origin": "dionaea.modules.python.mssql.cmd",
            "timestamp": "2026-04-24T18:12:30.000000",
            "data": {
                "connection": {
                    "id": "mssql-conn-1",
                    "local_ip": "10.0.2.10",
                    "local_port": 1433,
                    "remote_ip": "172.21.0.11",
                    "remote_port": 40211,
                    "remote_hostname": "",
                    "protocol": "mssqld",
                    "transport": "tcp",
                },
                "cmd": "select @@version",
                "status": "ok",
            },
        }
    )
    smb_line = json.dumps(
        {
            "name": "dionaea",
            "origin": "dionaea.modules.python.smb.dcerpc.request",
            "timestamp": "2026-04-24T18:13:00.000000",
            "data": {
                "connection": {
                    "id": "smb-conn-1",
                    "local_ip": "10.0.2.10",
                    "local_port": 445,
                    "remote_ip": "172.21.0.11",
                    "remote_port": 40445,
                    "remote_hostname": "",
                    "protocol": "smbd",
                    "transport": "tcp",
                },
                "uuid": "3919286a-b10c-11d0-9ba8-00c04fd92ef5",
                "opnum": 9,
            },
        }
    )

    assert await process_dionaea_log_line(login_line, honeypot_ip="10.0.2.10", db_factory=fake_db_factory)
    assert await process_dionaea_log_line(command_line, honeypot_ip="10.0.2.10", db_factory=fake_db_factory)
    assert await process_dionaea_log_line(smb_line, honeypot_ip="10.0.2.10", db_factory=fake_db_factory)
    await integration_db_session.commit()

    response = await integration_client.get(
        "/sessions",
        params={"page": 1, "page_size": 10, "honeypot": "dionaea", "ip": "172.21.0.11"},
    )
    assert response.status_code == 200

    items = response.json()["items"]
    assert len(items) == 2

    mssql_session = next(item for item in items if item["protocol"] == "mssql")
    smb_session = next(item for item in items if item["protocol"] == "smb")

    assert mssql_session["credentials_tried"] == [
        {"username": "sa", "password": "P@ssw0rd!", "success": False},
    ]
    assert [entry["command"] for entry in mssql_session["commands"]] == ["select @@version"]
    assert smb_session["commands"][0]["command"] == (
        "DCERPC request 3919286a-b10c-11d0-9ba8-00c04fd92ef5 opnum 9"
    )
