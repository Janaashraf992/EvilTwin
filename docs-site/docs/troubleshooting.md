# Troubleshooting Guide

This guide maps common symptoms to likely causes and step-by-step remediation. Start with the symptom that most closely matches what you're seeing.

:::tip Quick health check
Before diving into specific symptoms, run these two commands — they rule out 80% of issues:
```bash
curl -s http://localhost:8000/health
docker compose ps
```
:::

---

## Authentication Issues

### Symptom: API returns `401 Unauthorized`

**Meaning**: Your request is missing a valid JWT token, the token has expired, or the signature no longer matches.

**Cause 1: Token expired (most common)**
JWT access tokens expire after 30 minutes by default. Your frontend should refresh them automatically via `POST /auth/refresh`. If you are using curl manually, you need to fetch a new token.

```bash
# Re-authenticate to get a fresh token
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "YourPassword"}'
# Copy the new access_token value
```

**Cause 2: SECRET_KEY changed**
If `SECRET_KEY` in `.env` was rotated or reset, all previously issued tokens are immediately invalid — they cannot be verified against the new key. All users must re-login.

**Cause 3: Missing Authorization header**
Every authenticated endpoint requires: `Authorization: Bearer <your_token>`. Missing either part returns 401.

```bash
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/sessions
```

---

### Symptom: API returns `403 Forbidden`

**Meaning**: Your token is valid, but your role (`viewer`, `analyst`, `admin`) does not have permission to perform that action.

```bash
# Check what role your account has by examining your token payload
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJ2aWV3ZXIifQ..." \
  | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
# Look for "role" in the output
```

Ask an admin to update your role if you need more permissions.

---

## Backend Issues

### Symptom: `GET /health` returns 503

**Meaning**: The backend is running but cannot reach the database.

| Step | Command |
|---|---|
| 1. Check Postgres container state | `docker compose ps postgres` |
| 2. View Postgres logs | `docker compose logs postgres --tail=50` |
| 3. Check backend startup logs | `docker compose logs backend --tail=100` |
| 4. Verify DB credentials in `.env` | `POSTGRES_PASSWORD`, `POSTGRES_DB`, `POSTGRES_USER` match |

**Most common fix**: Start Postgres first, wait for it to be healthy, then restart the backend:

```bash
docker compose up -d postgres
# Wait 10–15 seconds
docker compose restart backend
curl -s http://localhost:8000/health
```

---

### Symptom: `POST /log` returns 422 Unprocessable Entity

**Meaning**: The request payload failed Pydantic validation. A required field is missing, or a field has the wrong format.

Common field errors:

| Field | Required format | Bad example | Good example |
|---|---|---|---|
| `timestamp` | ISO 8601 UTC | `"2024-01-15"` | `"2024-01-15T10:00:00Z"` |
| `src_ip` | IPv4 dotted decimal | `"10.0.0"` | `"10.0.0.1"` |
| `protocol` | lowercase string | `"SSH"` | `"ssh"` |

View the full validation error message for the exact field that failed:

```bash
curl -v -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -d '{"your": "payload"}' 2>&1 | python3 -m json.tool
```

---

### Symptom: `/sessions` returns empty after ingestion

**Meaning**: Either the event was not stored, or you're filtering to a time range that doesn't match.

```bash
TOKEN="your_token_here"

# Step 1: Verify the log endpoint returned 200 (not 422 or 500)
# Step 2: Query sessions without any filter
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions?page=1&page_size=50" | python3 -m json.tool

# Step 3: Check database directly for any sessions
docker compose exec postgres psql -U eviltwin eviltwin \
  -c "SELECT COUNT(*), MIN(first_seen), MAX(first_seen) FROM sessions;"
```

If the database query returns 0 rows, run `alembic upgrade head` — the schema migration may not have been applied.

---

### Symptom: Migrations fail

**Meaning**: `alembic upgrade head` returns an error.

**Cause 1: Database not running**

```bash
docker compose ps postgres   # Should show "healthy"
docker compose up -d postgres
```

**Cause 2: Schema already exists in wrong state**

```bash
# Check what revision Alembic thinks the database is at
docker compose exec backend alembic current

# If you see "(head)" it's already up to date
# If you see an error about missing tables, the alembic_version table may be corrupt
docker compose exec postgres psql -U eviltwin eviltwin \
  -c "SELECT * FROM alembic_version;"
```

---

## AI / LLM Issues

### Symptom: `POST /ai/analyze` returns `503 Service Unavailable`

**Meaning**: The LLM (AI) service is configured as unavailable, or the API key is wrong.

```bash
TOKEN="your_token_here"

# Step 1: Check AI module status
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/ai/status
# If "available": false — check LLM_API_KEY and LLM_BASE_URL

# Step 2: Test your LLM API key directly
curl -H "Authorization: Bearer $LLM_API_KEY" \
  -H "Content-Type: application/json" \
  "${LLM_BASE_URL}/models"
```

**Cause 1: `LLM_API_KEY` not set or wrong**
Set `LLM_API_KEY=sk-...` in `.env` and restart the backend.

**Cause 2: Using a local Ollama instance — wrong base URL**
If using Ollama locally, set:
```bash
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3.2
```
Note: Use `host.docker.internal` from inside Docker containers, not `localhost`.

---

## Frontend Issues

### Symptom: Dashboard shows "Disconnected" or no live alerts

**Meaning**: The WebSocket connection to the backend is not established.

WebSocket connections in EvilTwin require JWT authentication. The URL is:
```
ws://localhost:8000/ws/alerts?token=<your_jwt_token>
```

| Check | How to verify |
|---|---|
| Backend running | `curl -s http://localhost:8000/health` |
| Correct WS URL | Check `VITE_WS_URL` in `frontend/.env` |
| Valid token | Open DevTools → Application → Local Storage → check `access_token` |
| Token not expired | Decode with `echo '<token>' \| cut -d'.' -f2 \| base64 -d` and check `exp` field |

---

### Symptom: Login page accepts credentials but immediately redirects back to login

**Meaning**: The JWT token the backend returned is not being stored correctly.

1. Open browser DevTools → Network tab
2. Attempt login and observe the `POST /auth/login` response
3. If the response is `401`, you typed the wrong password
4. If the response is `200` but login still fails, the frontend is not saving the token — clear `localStorage` and try again:

```javascript
// In the browser console:
localStorage.clear();
```

---

### Symptom: Session list shows but page looks broken

**Likely cause**: The frontend build is stale. Rebuild after pulling new code:

```bash
cd frontend
npm install   # install any new dependencies
npm run dev   # or npm run build for production
```

---

## SDN / Network Issues

### Symptom: No redirect for suspicious IP

| Step | Command/Action |
|---|---|
| 1. Verify the IP's threat level | `curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/score/203.0.113.1` |
| 2. Check the redirect threshold | `grep THREAT_REDIRECT_THRESHOLD .env` (default is `3`) |
| 3. Inspect installed flows | `curl http://localhost:8080/stats/flow/1` (Ryu REST API) |
| 4. Check controller connectivity | `docker compose logs ryu --tail=50` |

The controller only installs redirect rules for IPs with `threat_level >= THREAT_REDIRECT_THRESHOLD`. If the score is lower, behavior is correct.

### Symptom: SDN controller cannot reach backend

**Error in Ryu logs**: `ConnectionRefusedError` or `Cannot connect to backend`

The controller uses an internal Docker network to reach the backend. Verify:

```bash
docker compose exec ryu ping backend -c 3
# Should succeed — if it fails, the containers are on different networks
```

---

## Testing Issues

### Symptom: Integration tests are skipped

**Cause**: `TEST_DATABASE_URL` is not set in the environment.

```bash
export TEST_DATABASE_URL='postgresql+asyncpg://eviltwin:password@localhost:5432/eviltwin_test'
pytest backend/tests/test_api_integration.py -v
```

### Symptom: Tests fail with `ModuleNotFoundError: No module named 'jose'`

```bash
# Install all backend dependencies in your local virtual environment
source .venv/bin/activate
pip install "python-jose[cryptography]" passlib[bcrypt] openai
```

