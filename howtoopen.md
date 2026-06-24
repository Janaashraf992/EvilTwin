# How to Run EvilTwin

## Prerequisites

- Docker Desktop installed and running
- Git installed
- Ports 22, 2222, 3000, 5432, 6633, 8000, 8080, 8081, 8082, 8088, 8089, 8888, 18000, 18088 free

## 1. Clone and Setup

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
cp .env.example .env
```

Set required secrets in `.env`:
```env
POSTGRES_PASSWORD=changeme
SECRET_KEY=change-me-in-production
CANARY_WEBHOOK_SECRET=change-me-in-production
```

Generate strong secrets:
```bash
openssl rand -hex 32
```

## 2. Start the Stack

```bash
docker compose up --build -d
```

Wait ~30-40 seconds for everything to start.

## 3. Verify

```bash
curl http://localhost:8000/health
# {"status":"healthy","database":true,"model":true}
```

## 4. Open Dashboard

```
http://localhost:3000
```

Login:
| Field | Value |
|-------|-------|
| Email | analyst@eviltwin.local |
| Password | eviltwin-demo |

## Services & Ports

| Service | Port | Purpose |
|---------|------|---------|
| Frontend | 3000 | SOC Dashboard |
| Backend API | 8000 | FastAPI REST + WebSocket |
| API Docs | 8000/docs | Swagger UI |
| PostgreSQL | 5432 | Database |
| SSH Gateway | 22 | Pre-session scoring + routing |
| Cowrie SSH | 2222 | SSH honeypot (direct) |
| HTTP Gateway | 8888 | Per-IP HTTP routing |
| Dionaea FTP | 2121 | FTP honeypot |
| Dionaea HTTP | 8081 | HTTP honeypot (direct) |
| Dionaea SMB | 1445 | SMB honeypot |
| Dionaea MSSQL | 11433 | MSSQL honeypot |
| Tripwire | 8082 | Canary bait server |
| Dummy Real SSH | 8022 | Real server SSH banner |
| Dummy Real HTTP | 8088 | Real server web page |
| Ryu SDN | 8080 | SDN controller REST |
| Splunk Ent | 18000 | Splunk Enterprise |
| Splunk HEC | 8089 | HEC event collector |

## Architecture

```
Attacker → SSH Gateway (22)  → scoring → Cowrie (honeypot) or dummy-real (real)
Attacker → HTTP Gateway (8888) → routing → Dionaea HTTP or dummy-real
Attacker → FTP (2121) → Dionaea (always honeypot)
Attacker → SMB (1445) → Dionaea (always honeypot)
Attacker → MSSQL (11433) → Dionaea (always honeypot)
Attacker → HTTP (8082) → Tripwire (benign web bug + leaked /.git secret)
```

## Canary Token Levels (graduated deception)

Bait is no longer dumped in one open directory. Each canary token is a "level"
whose real access difficulty matches its declared threat difficulty. Reaching
any of them fires an alert (weighted by difficulty) to the dashboard.

| Lvl | Difficulty | Surface (port) | Bait | How to reach it |
|-----|-----------|----------------|------|-----------------|
| 0 | 0 Benign | Tripwire HTTP (8082) | benign tracking pixel | just open `http://host:8082/` |
| 1 | 1 Easy | Dionaea HTTP (8081) | `passwords.txt` | `GET /passwords.txt` on the web honeypot |
| 2 | 2 Moderate | Dionaea FTP (2121) | `aws_credentials` | anonymous FTP, `RETR aws_credentials` |
| 3 | 3 High | Tripwire HTTP (8082) | `.env.production` | discover the exposed `/.git/`, then fetch `/.env.production` |
| 4 | 3 High | Cowrie SSH (2222) | `database_backup.sql` | log in, `cat /tmp/database_backup.sql` |
| 5 | 4 Critical | Cowrie SSH (2222) | `id_rsa` | root session, `cat /root/.ssh/id_rsa` |

- Levels 0 and 3 fire via the tripwire's HMAC webhook (`TRIPWIRE_TOKEN_MAP`).
- Levels 1, 2, 4, 5 fire from backend honeypot-log detection
  (`backend/services/canary.py`, override via `CANARY_BAIT_MAP`).
- The tripwire directory listing is disabled — only the benign index page is
  openly browsable; the `/.git/` and `/.env.production` paths must be discovered.

## SSH Credentials (for testing real path)

| Username | Password | Result |
|----------|----------|--------|
| real | eviltwin | Real server (Ubuntu banner) |
| root/admin/test | anything | Cowrie honeypot |

## Stopping

```bash
docker compose down          # Stop containers
docker compose down -v       # Also remove volumes (database)
```

## Testing from LAN

1. Find your LAN IP: `ipconfig` (Windows) / `ip a` (Linux)
2. Ensure Windows Firewall allows the ports (see `.env` comments)
3. Friends connect to `192.168.x.x` with ports above
4. All traffic is scored, routed, and logged to the dashboard

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Port in use | Stop conflicting process or change port in `.env` |
| Backend unhealthy | `docker compose logs backend` |
| Database error | Ensure `POSTGRES_PASSWORD` set in `.env` |
| Frontend blank | Check browser console; backend on port 8000 |
| Canary not firing | Restart tripwire: `docker compose restart tripwire` |
