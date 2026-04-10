---
id: developer-onboarding
title: Developer Onboarding
---

# Developer Onboarding

This guide gets a new developer productive in about 20 minutes. By the end you will have:
- All services running locally via Docker
- A database with schema applied
- A working login token
- A test event ingested and scored
- (Optional) LLM AI assistant configured

---

## Prerequisites

Before starting, install the following on your machine:

| Tool | Minimum Version | Install |
|---|---|---|
| Docker | 24+ | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| Docker Compose | v2 (plugin) | Included with Docker Desktop; `apt install docker-compose-plugin` on Linux |
| Python | 3.11+ | [python.org](https://www.python.org) |
| Node.js | 20+ | [nodejs.org](https://nodejs.org) |
| npm | 10+ | Included with Node.js |

**Optional but recommended:**
- `psql` (PostgreSQL client) — useful for inspecting the database directly
- `jq` — makes reading JSON API responses much easier (`apt install jq` / `brew install jq`)

---

## Step 1 — Clone and Configure

```bash
git clone <your-repo-url>
cd "Evil Twin"

# Create your local environment file from the example
cp .env.example .env
```

Now open `.env` and set these required values:

```bash
# Change the database password
POSTGRES_PASSWORD=changeme123

# Generate a secure SECRET_KEY (used to sign JWT tokens)
# Run this command and paste the output into .env:
openssl rand -hex 32
SECRET_KEY=<paste output here>

# Generate a secure canary webhook secret
openssl rand -hex 32
CANARY_WEBHOOK_SECRET=<paste output here>
```

**Optional (leave empty for local development):**
```bash
IPINFO_TOKEN=             # IP geolocation (works without it, returns defaults)
ABUSEIPDB_API_KEY=        # IP reputation (works without it)
LLM_API_KEY=              # For AI analysis features (see Step 6 below)
```

:::note Why do I need SECRET_KEY?
SECRET_KEY is used to cryptographically sign JWT tokens. If it changes, all existing tokens become invalid and users need to log in again. Generate it once and keep it stable per environment.
:::

---

## Step 2 — Start Core Services

```bash
docker compose up --build -d
```

This starts: `postgres`, `backend`, `cowrie`, `dionaea`, `ryu`, and `nginx` containers.

Wait about 15 seconds for services to initialise, then verify:

```bash
docker compose ps
# All services should show "running" or "healthy"

curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected health response:
```json
{
  "status": "ok",
  "database": true,
  "model_loaded": true,
  "uptime_seconds": 12
}
```

If `database: false`, PostgreSQL is not ready yet. Wait a few more seconds and retry.

---

## Step 3 — Apply Database Migrations

The database schema is managed by Alembic. Run migrations once after first startup:

```bash
# From the repo root
docker compose exec backend alembic upgrade head
```

This creates all tables: `users`, `attacker_profiles`, `session_logs`, `alerts`.

To verify tables were created:
```bash
docker compose exec postgres psql -U postgres -d eviltwin -c "\dt"
```

---

## Step 4 — Create Your First User Account

Register an admin account (requires the backend to be running):

```bash
# First, get a bootstrap token if auth is required, or use the registration endpoint directly
curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "SecurePass123!",
    "role": "admin"
  }' | python3 -m json.tool
```

Then log in to get your JWT token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@example.com", "password": "SecurePass123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Your token: $TOKEN"
```

Save `$TOKEN` — you'll use it for all subsequent API calls in this session.

---

## Step 5 — Start the Frontend

```bash
cd frontend
npm install
npm run dev
```

Open the dashboard at **http://localhost:5173**. Log in with the credentials you created in Step 4.

:::note Port 5173
The frontend runs on port 5173 (Vite's default), not the traditional port 3000.
:::

---

## Step 6 — (Optional) Configure LLM AI Assistant

To use `POST /ai/analyze` and `POST /ai/chat`, you need either an OpenAI API key or a local Ollama instance.

**Option A — OpenAI:**
```bash
# Add to .env
LLM_API_KEY=sk-...your-openai-key...
LLM_MODEL=gpt-4o-mini
```

**Option B — Local Ollama (free, private):**
```bash
# 1. Install Ollama: https://ollama.ai
ollama pull llama3.2
ollama serve          # starts on localhost:11434

# 2. Add to .env
LLM_API_KEY=ollama
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=llama3.2
```

After updating `.env`, restart the backend:
```bash
docker compose restart backend
```

Verify:
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://localhost:8000/ai/status | python3 -m json.tool
```

---

## Step 7 — Smoke Test the Full Pipeline

Run these commands to verify end-to-end functionality:

```bash
# 1. Ingest a test attack event
curl -s -X POST http://localhost:8000/log \
  -H "Content-Type: application/json" \
  -d '{
    "eventid": "cowrie.command.input",
    "src_ip": "203.0.113.10",
    "src_port": 50555,
    "dst_ip": "10.0.2.10",
    "dst_port": 22,
    "session": "dev-test-session-01",
    "protocol": "ssh",
    "timestamp": "2026-03-18T10:00:00Z",
    "input": "cat /etc/shadow",
    "username": "root",
    "password": "toor"
  }' | python3 -m json.tool

# 2. See the attacker's threat score
curl -s "http://localhost:8000/score/203.0.113.10" | python3 -m json.tool

# 3. List sessions (requires auth)
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions?page=1&page_size=5" | python3 -m json.tool

# 4. Dashboard stats
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/dashboard/stats" | python3 -m json.tool

# 5. If LLM is configured: AI analysis
curl -s -X POST http://localhost:8000/ai/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "session_id": "dev-test-session-01",
    "src_ip": "203.0.113.10",
    "commands": ["cat /etc/shadow"],
    "credentials": [{"username": "root", "password": "toor"}],
    "threat_score": 0.7,
    "threat_level": 3,
    "duration_seconds": 30,
    "vpn_detected": false
  }' | python3 -m json.tool
```

---

## Step 8 — Run Tests

**Backend tests:**
```bash
# From repo root
pytest backend/tests -q
```

Integration tests that write to the database require `TEST_DATABASE_URL`:
```bash
TEST_DATABASE_URL=postgresql+asyncpg://postgres:changeme123@localhost:5432/eviltwin_test \
  pytest backend/tests -q
```

**Frontend tests:**
```bash
cd frontend
npm test -- --run
npm run build
```

**SDN tests:**
```bash
pytest sdn/tests -q
```

---

## Step 9 — Set Up Your Local Python Environment

For IDE support (auto-complete, linting) without Docker:

```bash
python3 -m venv .venv
source .venv/bin/activate

pip install -r backend/requirements.txt
pip install "python-jose[cryptography]" passlib[bcrypt] openai pytest pytest-asyncio
```

Run ruff linting:
```bash
ruff check backend/
```

---

## Daily Development Workflow

```bash
# Pull latest changes
git pull

# Rebuild if requirements changed
docker compose up --build -d

# Re-run migrations if new versions exist
docker compose exec backend alembic upgrade head

# Run all checks before committing
pytest backend/tests -q && \
  cd frontend && npm test -- --run && npm run build && \
  pytest sdn/tests -q
```

---

## Common Issues

| Symptom | Cause | Fix |
|---|---|---|
| `database: false` in `/health` | PostgreSQL not ready | Wait 10s, retry |
| `401 Unauthorized` | Token missing or expired | Re-run login command to get a new token |
| `503` from `/ai/*` | LLM not configured | Set `LLM_API_KEY` in `.env` and `docker compose restart backend` |
| `ModuleNotFoundError: ryu` | Running SDN tests without `ryu` | Run inside container: `docker compose exec ryu pytest tests/` |
| `alembic: already up to date` | Migrations already applied | Normal — no action needed |
| Frontend shows blank page | Build error or wrong API URL | Check browser console; verify backend is on port 8000 |

See [Troubleshooting](/docs/troubleshooting) for more detailed diagnosis.
