# How to Run EvilTwin

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- [Git](https://git-scm.com/) installed
- Ports `2222`, `2121`, `8081`, `1445`, `11433`, `8000`, `3000`, `5432`, `6633`, `8080` free on your machine

---

## 1. Clone the Repository

```bash
git clone https://github.com/Janaashraf992/EvilTwin.git
cd EvilTwin
```

---

## 2. Create the Environment File

Copy the example env file and open it:

```bash
cp .env.example .env
```

Set the three **required** secrets inside `.env`:

```env
POSTGRES_PASSWORD=changeme
SECRET_KEY=change-me-in-production
CANARY_WEBHOOK_SECRET=change-me-in-production
```

> To generate strong secrets you can run:
> ```bash
> openssl rand -hex 32
> ```

---

## 3. Start the Stack

```bash
docker compose up --build -d
```

This will build and start all services:
- PostgreSQL database
- Cowrie SSH honeypot
- Dionaea multi-protocol honeypot
- FastAPI backend
- React frontend dashboard
- Ryu SDN controller

Check that all containers are running:

```bash
docker compose ps
```

---

## 4. Verify the Backend is Healthy

```bash
curl -s http://localhost:8000/health
```

Wait until it returns a healthy response (may take ~30–40 seconds on first start).

---

## 5. Open the Dashboard

Navigate to:

```
http://localhost:3000
```

Log in with the seeded demo account:

| Field    | Value                   |
| -------- | ----------------------- |
| Email    | `analyst@eviltwin.local` |
| Password | `eviltwin-demo`          |

---

## Services & Ports

| Service        | URL / Port          | Purpose                          |
| -------------- | ------------------- | -------------------------------- |
| Frontend       | http://localhost:3000 | SOC dashboard                  |
| Backend API    | http://localhost:8000 | FastAPI REST + WebSocket API   |
| API Docs       | http://localhost:8000/docs | Swagger UI                |
| PostgreSQL     | `localhost:5432`    | Database                         |
| Cowrie (SSH)   | `localhost:2222`    | SSH honeypot                     |
| Dionaea FTP    | `localhost:2121`    | FTP honeypot                     |
| Dionaea HTTP   | `localhost:8081`    | HTTP honeypot                    |
| Dionaea SMB    | `localhost:1445`    | SMB honeypot                     |
| Dionaea MSSQL  | `localhost:11433`   | MSSQL honeypot                   |
| Ryu REST       | http://localhost:8080 | SDN controller REST API        |

---

## Stopping the Stack

```bash
docker compose down
```

To also remove all stored data (database volumes):

```bash
docker compose down -v
```

---

## Optional: Run Frontend in Dev Mode (without Docker)

```bash
cd frontend
npm install
npm run dev
```

The dev server starts at `http://localhost:5173`.

Make sure the backend is running (via Docker) and set in `frontend/.env`:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws/alerts
```

---

## Optional: Run Backend Locally (without Docker)

Requires Python 3.11+ and a running PostgreSQL instance.

```bash
cd backend
pip install -r requirements.txt
```

Create a `.env` file in `backend/` with your database credentials, then:

```bash
alembic upgrade head
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Troubleshooting

| Problem | Fix |
| ------- | --- |
| Port already in use | Stop the conflicting process or change the port in `.env` |
| Backend not healthy after 2 min | Run `docker compose logs backend` to see errors |
| Database connection refused | Make sure `POSTGRES_PASSWORD` in `.env` is set |
| Frontend blank page | Check browser console; ensure backend is reachable on port 8000 |
| `POSTGRES_PASSWORD is required` error | You forgot to copy `.env.example` to `.env` |
