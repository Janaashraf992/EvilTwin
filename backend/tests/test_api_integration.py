import uuid
from datetime import datetime, timezone

import pytest


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
