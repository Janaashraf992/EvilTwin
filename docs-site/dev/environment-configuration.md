---
id: environment-configuration
title: Environment Configuration
sidebar_position: 13
slug: /environment-configuration
---

# Environment Configuration

EvilTwin is configured entirely through environment variables loaded from a `.env` file. This document describes every variable, its type, its default value, and when you must change it.

:::tip Generating secrets
Never use default or guessable values for secrets. Generate them:
```bash
openssl rand -hex 32   # 64-character hex string — good for SECRET_KEY, CANARY_WEBHOOK_SECRET
openssl rand -hex 20   # For POSTGRES_PASSWORD
```
:::

## Configuration Principles

- Defaults are safe for local development, **not** for production
- Backend startup validation (via Pydantic Settings) will fail fast if a required value is missing
- Optional integrations log their enabled/disabled state on startup
- Never commit real secrets to git — `.env` is in `.gitignore`

---

## Database

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `POSTGRES_HOST` | string | `postgres` | No | PostgreSQL hostname (Docker service name in Compose) |
| `POSTGRES_PORT` | int | `5432` | No | PostgreSQL port |
| `POSTGRES_DB` | string | `eviltwin` | No | Database name |
| `POSTGRES_USER` | string | `eviltwin` | No | Database user |
| `POSTGRES_PASSWORD` | string | — | **Yes** | Database password — change before production |

---

## Authentication and JWT

EvilTwin uses [JSON Web Tokens (JWT)](https://jwt.io/introduction) for user authentication. These variables control how tokens are signed and when they expire.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `SECRET_KEY` | string | — | **Yes** | The HMAC secret used to sign all JWT tokens. Changing this invalidates all existing sessions. Generate with `openssl rand -hex 32`. |
| `ALGORITHM` | string | `HS256` | No | JWT signing algorithm. `HS256` is secure for most deployments. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | int | `30` | No | Minutes until an access token expires. Shorter = more secure but requires more refreshes. |
| `REFRESH_TOKEN_EXPIRE_DAYS` | int | `7` | No | Days until a refresh token expires. Users must re-login after this period. |

:::warning Rotating SECRET_KEY in production
If you rotate `SECRET_KEY`, all currently logged-in users will be immediately logged out — their tokens will fail signature verification. Plan rotations for maintenance windows and communicate to users.
:::

---

## CORS (Cross-Origin Resource Sharing)

CORS controls which web origins (domains) are allowed to make requests to the backend API. This matters when your frontend is served from a different domain than your backend.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `CORS_ORIGINS` | string (comma-separated URLs) | `http://localhost:5173` | No | Allowed frontend origins. In production, set this to your actual frontend domain, e.g. `https://soc.example.com`. |

**Example for production:**
```bash
CORS_ORIGINS=https://soc.example.com,https://soc-backup.example.com
```

:::warning Do not use wildcard `*` in production
Setting `CORS_ORIGINS=*` allows any website to make requests to your API, which is a security risk. Always specify exact origins.
:::

---

## SDN and Threat Evaluation

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `RYU_REST_URL` | string | `http://ryu:8080` | No | SDN controller REST API URL |
| `HONEYPOT_IP` | string | `10.0.2.10` | No | IP to redirect suspicious traffic to |
| `REAL_NET_CIDR` | string | `10.0.1.0/24` | No | Your real production network CIDR — used to avoid accidentally redirecting legitimate traffic |
| `THREAT_REDIRECT_THRESHOLD` | int | `3` | No | Minimum threat level (0–4) that triggers SDN redirection. Lower = more aggressive. |
| `SCORE_CACHE_TTL` | int | `300` | No | Seconds to cache threat scores before re-computing (reduces DB load) |
| `MODEL_PATH` | string | `/app/ai/model.pkl` | No | Path to the trained ML model file |

---

## LLM / AI Assistant

EvilTwin can integrate with any OpenAI-compatible LLM API for natural language threat analysis. If these variables are not set, AI endpoints return `503` with `{"available": false}`.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `LLM_API_KEY` | string | — | No | API key for the LLM provider (OpenAI, Anthropic via proxy, Ollama, etc.) |
| `LLM_BASE_URL` | string | `https://api.openai.com/v1` | No | Base URL of the OpenAI-compatible API |
| `LLM_MODEL` | string | `gpt-4o-mini` | No | Model name to use for threat analysis |
| `LLM_MAX_TOKENS` | int | `2000` | No | Maximum tokens per LLM response |
| `LLM_TEMPERATURE` | float | `0.3` | No | Response randomness (0.0 = deterministic, 1.0 = creative). 0.3 is good for analysis. |

**Using OpenAI (cloud):**
```bash
LLM_API_KEY=sk-proj-...
LLM_BASE_URL=https://api.openai.com/v1
LLM_MODEL=gpt-4o-mini
```

**Using Ollama (local, free):**
```bash
LLM_API_KEY=ollama
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=llama3.2
```

:::tip Using Ollama for no-cost local AI
[Ollama](https://ollama.com) runs LLMs locally on your machine with no API costs. Install it, then `ollama pull llama3.2`, and use the URL above. Use `host.docker.internal` because Docker containers can't use `localhost` to reach the host machine.
:::

---

## Canary Webhooks

Canary tokens are unique tracked identifiers embedded in files or links. When triggered, they call back to EvilTwin's webhook endpoint.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `CANARY_WEBHOOK_SECRET` | string | — | **Yes** | HMAC-SHA256 secret shared with your canary service. Used to verify that webhook requests came from the right source. |
| `CANARY_WEBHOOK_TOLERANCE_SECONDS` | int | `300` | No | Maximum age of a webhook request (in seconds). Requests older than this are rejected to prevent replay attacks. |

---

## External Threat Intelligence

These variables enable enrichment of attacker IPs with geographic and reputation data. All are optional; if missing, enrichment is skipped gracefully.

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `IPINFO_TOKEN` | string | — | No | [IPInfo](https://ipinfo.io) API token for country/ASN/VPN detection |
| `ABUSEIPDB_API_KEY` | string | — | No | [AbuseIPDB](https://www.abuseipdb.com) key for IP reputation scoring |

---

## Splunk Integration

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `SPLUNK_HEC_URL` | string | — | No | Splunk HTTP Event Collector endpoint URL |
| `SPLUNK_HEC_TOKEN` | string | — | No | Splunk HEC authentication token |

When both are set, the backend forwards enriched session events to Splunk automatically.

---

## Frontend Variables

These variables are used by the Vite-based React frontend (prefix `VITE_` makes them available in browser code).

| Variable | Type | Default | Description |
|---|---|---|---|
| `VITE_API_BASE_URL` | string | `http://localhost:8000` | Backend API base URL |
| `VITE_WS_URL` | string | `ws://localhost:8000/ws/alerts` | WebSocket URL for live alerts |

In production, update these to your actual domain:
```bash
VITE_API_BASE_URL=https://api.soc.example.com
VITE_WS_URL=wss://api.soc.example.com/ws/alerts
```

Note: `wss://` is WebSocket over HTTPS (encrypted), equivalent to `https://`. Always use `wss://` in production.

---

## Deployment Configuration Profiles

### Local Development

```bash
# Minimal .env for local dev
POSTGRES_PASSWORD=devpassword
SECRET_KEY=dev_secret_key_not_for_production_12345678901234567890
CANARY_WEBHOOK_SECRET=dev_canary_secret
CORS_ORIGINS=http://localhost:5173
# Leave LLM vars unset to skip AI features, or set LLM_API_KEY for testing
```

### Production

```bash
# Production .env — use real secrets
POSTGRES_PASSWORD=$(openssl rand -hex 20)
SECRET_KEY=$(openssl rand -hex 32)
CANARY_WEBHOOK_SECRET=$(openssl rand -hex 32)
CORS_ORIGINS=https://soc.example.com
VITE_API_BASE_URL=https://api.soc.example.com
VITE_WS_URL=wss://api.soc.example.com/ws/alerts

# LLM integration (optional but recommended)
LLM_API_KEY=sk-proj-...
LLM_MODEL=gpt-4o-mini

# Threat intelligence enrichment
IPINFO_TOKEN=your_token_here
ABUSEIPDB_API_KEY=your_key_here

# Optional: Splunk forwarding
SPLUNK_HEC_URL=https://splunk.example.com:8088/services/collector/event
SPLUNK_HEC_TOKEN=your_splunk_token
```

---

## Startup Validation Checklist

Before starting the platform, verify these:

```bash
# 1. Required secrets are set
grep -E "POSTGRES_PASSWORD|SECRET_KEY|CANARY_WEBHOOK_SECRET" .env \
  | grep -v "changeme\|your_"   # Should print all 3 lines

# 2. Docker Compose can parse the configuration
docker compose config > /dev/null && echo "Config OK"

# 3. Validate the backend sees expected settings
curl -s http://localhost:8000/health | python3 -m json.tool

# 4. Check AI service status
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8000/ai/status
```
