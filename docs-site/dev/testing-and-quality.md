---
id: testing-and-quality
title: Testing and Quality Strategy
---

# Testing and Quality Strategy

## Goals

This platform handles security-critical logic — incorrect threat scoring, broken auth, or dropped events could mean missed detections or denied access for analysts. The test suite is designed to catch regressions at every layer.

Test goals:
- **Ingestion correctness** — no events dropped or corrupted during the ingest pipeline
- **Auth and RBAC** — protected endpoints reject unauthenticated/unauthorised requests
- **Threat scoring** — ML model and feature extraction produce correct outputs
- **Alert delivery** — High/Critical events broadcast over WebSocket
- **Frontend behaviour** — analyst-critical workflows (filters, pagination, auth) work correctly
- **SDN logic** — flow rule installation/deletion is correct

---

## Test Pyramid

```mermaid
flowchart TD
    U[Unit Tests<br>Fast, isolated, no DB] --> I[Integration Tests<br>API + real PostgreSQL]
    I --> E[Runtime Validation<br>Containerised service and network paths]
```

Use unit tests for logic. Use integration tests for database and HTTP interactions. Use runtime validation sparingly — only where container behaviour cannot be mocked.

---

## Backend Tests

### Unit Tests (`backend/tests/`)

| Test File | What It Covers |
|---|---|
| `test_ai.py` | Feature extraction, scorer fallback when model missing |
| `test_scoring.py` | ML scoring output range, level classification |
| `test_alert_manager.py` | Queue push/pop, overflow behaviour, broadcast |
| `test_canary.py` | HMAC signature verification, replay attack detection |
| `test_vpn.py` | VPN detection service responses and mock |
| `test_train.py` | Synthetic data generation, model training, serialisation |

### Integration Tests (`backend/tests/test_api_integration.py` and `test_ingest.py`)

These tests spin up an ASGI test client and run actual HTTP requests against a real (schema-isolated) PostgreSQL schema.

**Endpoints covered:**

| Endpoint | What Is Verified |
|---|---|
| `GET /health` | 200 OK, `database: true` |
| `POST /auth/register` | User created, bcrypt hash stored |
| `POST /auth/login` | Returns `access_token` and `refresh_token` |
| `POST /auth/refresh` | Returns new access token |
| `POST /log` | Event persisted, session created, score computed |
| `GET /sessions` | Pagination, filters, correct response schema |
| `GET /sessions/{id}` | Session detail with commands and credentials |
| `GET /score/{ip}` | Score returned for known and unknown IPs |
| `GET /dashboard/stats` | 24h aggregates |
| `GET /dashboard/top-attackers` | Sorted attacker list |
| `POST /canary/webhook` | HMAC-valid and invalid requests |
| `GET /ai/status` | LLM availability check |

**DB isolation strategy:**
- Each test creates and drops its own schema prefix
- SQLAlchemy `get_db` dependency is overridden to inject the test session
- Async test client via `httpx.AsyncClient` with ASGI transport
- Tests are **skipped automatically** when `TEST_DATABASE_URL` is not set — safe for CI environments without a running Postgres

**To run integration tests:**
```bash
TEST_DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/eviltwin_test \
  pytest backend/tests -q
```

### Auth and RBAC Tests

Key scenarios tested:
- `POST /sessions` without token → 401
- `POST /sessions` with analyst token → 200
- Admin-only endpoint with analyst token → 403
- Expired token → 401
- Valid refresh token → new access token

---

## Frontend Tests

Test framework: **Vitest** (Jest-compatible, Vite-native) + **React Testing Library**

| Test Area | File | What Is Tested |
|---|---|---|
| Alert feed | `test/alertFeed.test.tsx` | Zustand store updates render new alert rows |
| Auth guard | `test/authGuard.test.tsx` | Unauthenticated user redirected to `/login` |
| Sessions filters | `test/sessionsFilters.test.tsx` | UI controls produce correct API query params |
| Pagination | `test/pagination.test.tsx` | Prev/next increments `page` correctly |
| TopBar reconnect | `test/topBar.test.tsx` | Backoff state shows attempt count and countdown |
| Token refresh | `test/tokenRefresh.test.tsx` | 401 triggers refresh; request is retried |

Run frontend tests:
```bash
cd frontend
npm test -- --run    # CI mode (single pass)
npm test             # watch mode (development)
npm run build        # TypeScript + Vite build — catches type errors
```

---

## SDN Tests (`sdn/tests/`)

| Test File | What Is Tested |
|---|---|
| Flow rule construction | `OFPFlowMod` messages have correct match and action fields |
| Flow install/delete | `FlowManager` calls the correct Ryu datapath methods |
| REST API — GET `/flows` | Returns current suspicious IP list |
| REST API — POST `/flows` | Adds an IP to the flow table |
| REST API — DELETE `/flows/{ip}` | Removes a specific IP |
| Backend score parsing | Controller correctly parses `threat_level` from backend response |
| Containerised validation | Compose config valid, Ryu image buildable (opt-in only) |

Run SDN tests:
```bash
pytest sdn/tests -q

# Opt-in runtime validation (requires Docker)
RUN_DOCKER_VALIDATION=1 pytest sdn/tests/validate_runtime.py -q
```

---

## CI/CD Pipeline

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs on every push and pull request:

```mermaid
flowchart LR
    PR[Push or PR] --> LINT[ruff lint]
    LINT --> UNIT[Backend unit tests]
    UNIT --> INT[Backend integration tests<br>against Postgres service]
    INT --> FE[Frontend tests + build]
    FE --> SDN[SDN unit tests]
    SDN --> PASS[All checks pass]
```

**Pipeline stages:**

| Stage | Command | Failure Causes |
|---|---|---|
| Lint | `ruff check backend/` | Style violations, unused imports, undefined names |
| Backend unit tests | `pytest backend/tests -q` | Logic errors in scorer, alert manager, canary, VPN |
| Backend integration tests | `pytest backend/tests -q` with Postgres service | DB schema issues, API contract changes |
| Frontend tests | `npm test -- --run` | Component regression, broken hooks |
| Frontend build | `npm run build` | TypeScript errors, missing imports |
| SDN tests | `pytest sdn/tests -q` | Flow rule logic errors |

The pipeline blocks merge if **any stage fails**. This prevents broken code from reaching the main branch.

---

## Quality Gate — Run Locally Before Pushing

```bash
# From repo root
ruff check backend/

pytest backend/tests -q

cd frontend && npm test -- --run && npm run build && cd ..

pytest sdn/tests -q
```

All four commands should exit with code 0. If any fail, fix before pushing.

---

## Risk-Based Testing Priorities

Not all code is equally critical. These areas deserve the most thorough test coverage:

| Priority | Area | Why |
|---|---|---|
| P0 | Ingest pipeline (`POST /log`) | Core data collection — bugs cause data loss |
| P0 | Auth and token validation | Security boundary — bugs mean unauthorised access |
| P1 | Threat scoring output | Drives automated SDN response — wrong scores cause false redirects |
| P1 | Canary HMAC + replay | Security feature — bypass = undetected canary triggers |
| P2 | WebSocket delivery | Analyst visibility — broken alerts delay response |
| P2 | Session filter queries | Analyst workflow — broken filters mean missing data |
| P3 | Dashboard aggregations | Nice-to-have — wrong numbers are cosmetic, not security-critical |
