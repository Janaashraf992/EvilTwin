# EvilTwin

EvilTwin is an SDN-powered cyber deception platform that combines Cowrie and Dionaea honeypots, a FastAPI ingestion and scoring backend, a React SOC dashboard, and an optional Ryu controller for threat-driven traffic redirection.

## Quick Start

Clone the repository, copy the environment template, and set the three required secrets:

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
cp .env.example .env
```

Edit `.env` and set:

```env
POSTGRES_PASSWORD=changeme
SECRET_KEY=change-me-in-production
CANARY_WEBHOOK_SECRET=change-me-in-production
```

Then start the full stack:

```bash
docker compose up --build -d
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
```

Open the dashboard at `http://localhost:3000` and log in with the seeded demo analyst account:

```text
Email: analyst@eviltwin.local
Password: eviltwin-demo
```

## Demo Ports

These are the host ports your team can probe after cloning and starting the stack:

| Service | Host Port | Container Port | Purpose |
| --- | --- | --- | --- |
| Cowrie | `2222` | `22` | SSH honeypot |
| Dionaea FTP | `2121` | `21` | FTP deception sensor |
| Dionaea HTTP | `8081` | `80` | HTTP deception sensor |
| Dionaea SMB | `1445` | `445` | SMB deception sensor |
| Dionaea MSSQL | `11433` | `1433` | MSSQL deception sensor |
| Backend API | `8000` | `8000` | FastAPI API and WebSocket alerts |
| Frontend | `3000` | `3000` | SOC dashboard |
| PostgreSQL | `5432` | `5432` | Local database |
| Ryu | `6633`, `8080` | `6633`, `8080` | OpenFlow + REST control plane |

## What Works After Cloning

- backend auto-trains a fallback model if `MODEL_PATH` is missing
- backend runs migrations on startup
- backend seeds the demo analyst account when `DEMO_BOOTSTRAP=true`
- backend tails Cowrie and Dionaea logs via mounted volumes
- dashboard auth works against the real backend
- Kali-driven SSH, HTTP, FTP, and SMB-style demo traffic appears in `/sessions`

## Teammate Workflow

For the tested end-to-end workflow, use these docs in order:

1. [Running the Project](docs-site/docs/running-the-project.md)
2. [Kali Demo Walkthrough](docs-site/docs/kali-demo-walkthrough.md)
3. [Incident Response Runbook](docs-site/docs/incident-response-runbook.md)

## Validation Commands

After the stack is up, these commands confirm the main surfaces are working:

```bash
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
curl -s http://localhost:8081/ -o /dev/null -D -
printf 'USER anonymous\r\nPASS demo@example.com\r\nQUIT\r\n' | nc -nv localhost 2121
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

## Documentation

- [Getting Started](docs-site/docs/getting-started.md)
- [Running the Project](docs-site/docs/running-the-project.md)
- [Kali Demo Walkthrough](docs-site/docs/kali-demo-walkthrough.md)
- [Documentation Index](docs-site/docs/documentation-index.md)

## Stack

FastAPI, PostgreSQL, SQLAlchemy, Scikit-learn, React, TypeScript, Tailwind, Cowrie, Dionaea, Ryu, Docker Compose, and optional Splunk / OpenAI-compatible LLM integrations.
