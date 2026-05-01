---
id: getting-started
title: Getting Started
---

This guide is the shortest accurate path from a fresh clone to a working EvilTwin demo stack.

## Prerequisites

You only need these tools to run the full demo stack:

| Tool | Minimum Version | Why It Is Needed |
| --- | --- | --- |
| Docker Engine | 24+ | Runs the platform services |
| Docker Compose | v2 | Orchestrates the stack |
| `curl` | any | Verifies health and API endpoints |
| `openssl` | any | Generates secrets for `.env` |

Node.js and Python are only needed if you plan to run the frontend or backend outside Docker.

## Step 1 — Clone the Repository

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
cp .env.example .env
```

## Step 2 — Set the Required Secrets

Edit `.env` and set these values before starting the stack:

```bash
openssl rand -hex 20
openssl rand -hex 32
openssl rand -hex 32
```

Use those values for:

```env
POSTGRES_PASSWORD=replace-me
SECRET_KEY=replace-me
CANARY_WEBHOOK_SECRET=replace-me
```

## Step 3 — Start the Full Stack

```bash
docker compose up --build -d
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
```

Expected services:

- `eviltwin-postgres`
- `eviltwin-backend`
- `eviltwin-cowrie`
- `eviltwin-dionaea`
- `eviltwin-frontend`
- `eviltwin-ryu`

## Step 4 — Log In to the Dashboard

Open `http://localhost:3000` and sign in with the seeded demo analyst account:

```text
Email: analyst@eviltwin.local
Password: eviltwin-demo
```

The compose stack enables `DEMO_BOOTSTRAP=true`, so this account is created automatically during backend startup.

## Step 5 — Verify the API Login Flow

If you want an API token for testing, use the real form-encoded login flow:

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=analyst@eviltwin.local" \
  --data-urlencode "password=eviltwin-demo" \
  | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

echo "${TOKEN:0:24}..."
```

## Step 6 — Run a Real Attack Demo

The tested demo flow uses:

- Cowrie on host port `2222`
- Dionaea FTP on `2121`
- Dionaea HTTP on `8081`
- Dionaea SMB on `1445`

For the exact attacker commands and the expected dashboard/API behavior, continue with [Kali Demo Walkthrough](./kali-demo-walkthrough.md).

## Step 7 — Check Sessions and Scores

Once you have generated traffic, verify the backend captured it:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/sessions?page=1&page_size=10" | python3 -m json.tool
```

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8000/score/127.0.0.1" | python3 -m json.tool
```

## Port Reference

| Host Port | Service |
| --- | --- |
| `2222` | Cowrie SSH honeypot |
| `2121` | Dionaea FTP |
| `8081` | Dionaea HTTP |
| `1445` | Dionaea SMB |
| `11433` | Dionaea MSSQL |
| `3000` | React dashboard |
| `8000` | FastAPI backend |

## Where to Go Next

| I want to... | Go here |
| --- | --- |
| Run the most complete tested setup | [Running the Project](./running-the-project.md) |
| Demo attacks from Kali | [Kali Demo Walkthrough](./kali-demo-walkthrough.md) |
| Understand the whole platform | [Master Guide](./master-guide.md) |
| Respond to an alert | [Incident Response Runbook](./incident-response-runbook.md) |
| Troubleshoot startup or runtime issues | [Troubleshooting](./troubleshooting.md) |
