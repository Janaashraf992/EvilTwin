# EvilTwin

EvilTwin is a cyber deception lab that combines multi-protocol honeypots, a FastAPI ingestion and scoring backend, a React SOC dashboard, and an SDN control layer for threat-aware traffic steering.

## What It Does

- captures attacker activity from Cowrie and Dionaea
- normalizes honeypot events into a shared ingestion contract
- stores sessions, credentials, commands, and derived metadata in PostgreSQL
- scores activity with a ML model and enrichment pipeline
- presents the resulting activity in a dashboard suitable for demos and analyst workflows
- supports optional Splunk forwarding, canary webhooks, and OpenAI-compatible incident narratives

## Architecture At A Glance

- `cowrie` provides the SSH deception surface on host port `2222`
- `dionaea` provides FTP, HTTP, SMB, and MSSQL deception surfaces on host ports `2121`, `8081`, `1445`, and `11433`
- `backend` tails the honeypot logs, runs ingestion and scoring, and exposes the API on `http://localhost:8000`
- `frontend` serves the SOC dashboard on `http://localhost:3000`
- `postgres` stores sessions, attacker profiles, and alert data
- `ryu` is available for SDN-driven redirection workflows and controller integration

## Repository Layout

```text
.
├── backend/          FastAPI API, ingest pipeline, scoring, tests
├── frontend/         React dashboard
├── docs-site/        Docusaurus documentation site
├── honeypots/        Cowrie and Dionaea container definitions
├── sdn/              Ryu controller and flow-management logic
├── splunk/           Universal Forwarder configuration and dashboards
├── infra/            Deployment infrastructure assets
└── docker-compose.yml
```

## Quick Start

Clone the repository and create the root environment file:

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
cp .env.example .env
```

Set the required secrets in `.env`:

```env
POSTGRES_PASSWORD=changeme
SECRET_KEY=change-me-in-production
CANARY_WEBHOOK_SECRET=change-me-in-production
```

Start the stack:

```bash
docker compose up --build -d
docker compose ps
```

Confirm the backend is healthy:

```bash
curl -s http://localhost:8000/health | python3 -m json.tool
```

Open the dashboard at `http://localhost:3000` and use the seeded demo analyst account:

```text
Email: analyst@eviltwin.local
Password: eviltwin-demo
```

## Clone-And-Run Behavior

After a fresh clone and `docker compose up --build -d`, the default stack is expected to:

- run database migrations automatically
- seed the demo analyst account when `DEMO_BOOTSTRAP=true`
- auto-train a fallback model if `MODEL_PATH` is missing
- tail Cowrie and Dionaea logs from mounted volumes
- surface Kali-driven SSH, HTTP, FTP, SMB, and MSSQL-style activity in the dashboard and `/sessions`

## Services And Ports

| Service       | Host Port      | Container Port | Purpose                                   |
| ------------- | -------------- | -------------- | ----------------------------------------- |
| Cowrie        | `2222`         | `22`           | SSH honeypot                              |
| Dionaea FTP   | `2121`         | `21`           | FTP deception surface                     |
| Dionaea HTTP  | `8081`         | `80`           | HTTP deception surface                    |
| Dionaea SMB   | `1445`         | `445`          | SMB deception surface                     |
| Dionaea MSSQL | `11433`        | `1433`         | MSSQL deception surface                   |
| Backend API   | `8000`         | `8000`         | FastAPI API and alert/WebSocket endpoints |
| Frontend      | `3000`         | `3000`         | SOC dashboard                             |
| PostgreSQL    | `5432`         | `5432`         | Local database                            |
| Ryu           | `6633`, `8080` | `6633`, `8080` | OpenFlow and REST controller              |

## Smoke Tests

These commands give a fast sanity check after startup:

```bash
docker compose ps
curl -s http://localhost:8000/health | python3 -m json.tool
curl -s http://localhost:8081/ -o /dev/null -D -
printf 'USER anonymous\r\nPASS demo@example.com\r\nQUIT\r\n' | nc -nv 127.0.0.1 2121
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@localhost
```

If you want a reset to a clean local state:

```bash
docker compose down -v
docker compose up --build -d
```

## Demo Workflow

In the documentation website, use the docs in this order:

1. [Running the Project](docs-site/docs/running-the-project.md)
2. [Kali Demo Walkthrough](docs-site/docs/kali-demo-walkthrough.md)
3. [Incident Response Runbook](docs-site/docs/incident-response-runbook.md)

That path covers stack startup, attack simulation from a Kali VM, and how the activity should appear in the dashboard.

## Configuration Highlights

The root [.env.example](.env.example) is already set up for the local demo stack. The most important values are:

- `POSTGRES_PASSWORD`, `SECRET_KEY`, and `CANARY_WEBHOOK_SECRET` for a functional local deployment
- `DEMO_BOOTSTRAP`, `DEMO_USER_EMAIL`, and `DEMO_USER_PASSWORD` for seeded dashboard access
- `DIONAEA_FTP_PORT`, `DIONAEA_HTTP_PORT`, `DIONAEA_SMB_PORT`, and `DIONAEA_MSSQL_PORT` if you need different host port bindings
- `IPINFO_TOKEN` and `ABUSEIPDB_API_KEY` if you want enrichment and reputation lookups
- `LLM_API_KEY` and related `LLM_*` variables if you want AI-generated incident narratives
- `SPLUNK_HEC_URL` and `SPLUNK_HEC_TOKEN` if you want Splunk forwarding

## Common Commands

Start or rebuild everything:

```bash
docker compose up --build -d
```

Rebuild only the honeypots:

```bash
docker compose build cowrie dionaea
docker compose up -d --force-recreate cowrie dionaea
```

Watch backend logs:

```bash
docker compose logs -f backend
```

Check the running containers:

```bash
docker compose ps
```

## Documentation Map

- [Getting Started](docs-site/docs/getting-started.md)
- [Running the Project](docs-site/docs/running-the-project.md)
- [Kali Demo Walkthrough](docs-site/docs/kali-demo-walkthrough.md)
- [Operations and Deployment](docs-site/docs/operations-and-deployment.md)
- [Troubleshooting](docs-site/docs/troubleshooting.md)
- [Documentation Index](docs-site/docs/documentation-index.md)

## Tech Stack

FastAPI, SQLAlchemy, PostgreSQL, scikit-learn, React, TypeScript, Tailwind CSS, Cowrie, Dionaea, Ryu, Docker Compose, and optional Splunk plus OpenAI-compatible integrations.
