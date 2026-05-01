"""Tests for the log ingestion endpoint."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _load_fixture_events() -> list[dict]:
    with open(FIXTURE_DIR / "sample_cowrie_event.json") as f:
        return json.load(f)


@pytest.mark.asyncio
async def test_ingest_single_event(integration_client):
    """POST /log with a simple Cowrie command event creates a session."""
    payload = {
        "eventid": "cowrie.command.input",
        "src_ip": "192.0.2.50",
        "src_port": 12345,
        "dst_ip": "10.0.2.10",
        "dst_port": 22,
        "session": "test-ingest-001",
        "protocol": "ssh",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": "output",
        "input": "ls -la",
    }
    resp = await integration_client.post("/log", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "session_id" in data
    assert "threat_score" in data
    assert "threat_level" in data
    assert 0 <= data["threat_level"] <= 4


@pytest.mark.asyncio
async def test_ingest_creates_attacker_profile(integration_client):
    """Ingestion upserts an AttackerProfile row."""
    payload = {
        "eventid": "cowrie.login.success",
        "src_ip": "198.51.100.10",
        "src_port": 33333,
        "dst_ip": "10.0.2.10",
        "dst_port": 22,
        "session": "test-profile-001",
        "protocol": "ssh",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": "root",
        "password": "toor",
    }
    resp = await integration_client.post("/log", json=payload)
    assert resp.status_code == 200

    # The IP should be queryable via /score
    score_resp = await integration_client.get("/score/198.51.100.10")
    assert score_resp.status_code == 200
    assert score_resp.json()["ip"] == "198.51.100.10"


@pytest.mark.asyncio
async def test_ingest_accumulates_commands(integration_client):
    """Multiple events for the same session accumulate commands."""
    base = {
        "eventid": "cowrie.command.input",
        "src_ip": "203.0.113.99",
        "src_port": 54321,
        "dst_ip": "10.0.2.10",
        "dst_port": 22,
        "session": "test-accum-001",
        "protocol": "ssh",
    }

    for i, cmd in enumerate(["id", "whoami", "uname -a"]):
        payload = {
            **base,
            "timestamp": f"2026-03-18T10:00:{i*10:02d}Z",
            "input": cmd,
            "message": f"output-{i}",
        }
        resp = await integration_client.post("/log", json=payload)
        assert resp.status_code == 200

    # Fetch the session and verify commands
    ingest_data = resp.json()
    session_resp = await integration_client.get(f"/sessions/{ingest_data['session_id']}")
    assert session_resp.status_code == 200
    session = session_resp.json()
    assert len(session["commands"]) == 3


@pytest.mark.asyncio
async def test_ingest_records_credentials(integration_client):
    """Login events record credentials tried."""
    payload = {
        "eventid": "cowrie.login.failed",
        "src_ip": "203.0.113.88",
        "src_port": 44444,
        "dst_ip": "10.0.2.10",
        "dst_port": 22,
        "session": "test-cred-001",
        "protocol": "ssh",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "username": "admin",
        "password": "password123",
    }
    resp = await integration_client.post("/log", json=payload)
    assert resp.status_code == 200

    session_resp = await integration_client.get(f"/sessions/{resp.json()['session_id']}")
    creds = session_resp.json()["credentials_tried"]
    assert len(creds) >= 1
    assert creds[0]["username"] == "admin"


@pytest.mark.asyncio
async def test_ingest_full_fixture(integration_client):
    """Ingest all events from the full sample fixture."""
    events = _load_fixture_events()
    last_resp = None
    for event in events:
        resp = await integration_client.post("/log", json=event)
        assert resp.status_code == 200
        last_resp = resp

    assert last_resp is not None
    data = last_resp.json()
    assert "session_id" in data
