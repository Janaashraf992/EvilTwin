---
id: observability-and-slos
title: Observability and SLOs
---

# Observability and SLOs

## What Is Observability?

Observability means being able to understand what a system is doing from the outside, without having to guess. For a security platform three signals matter most:

- **Logs** — what happened and when
- **Metrics** — how fast, how often, how many
- **Alerts** — when something breaks an expectation

EvilTwin uses structured JSON logs (easily ingested by Splunk or any log platform), application-level metrics, and defined SLOs (Service Level Objectives) to make operational health transparent.

---

## Golden Signals

The four golden signals cover the health of any service:

| Signal | Metric | Tool |
|---|---|---|
| **Latency** | API p95 response time per endpoint | Application logs (timing middlware) |
| **Traffic** | Requests/s to `/log`, `/sessions`, `/ai/analyze` | Log aggregation |
| **Errors** | 4xx/5xx rate per endpoint | Log aggregation |
| **Saturation** | Database connection pool utilisation, queue depth in alert manager | Application state |

---

## Service Level Objectives (SLOs)

An SLO is a target that defines "acceptable" service. Breaching it means something needs attention.

| SLO | Target | Measurement Window |
|---|---|---|
| Ingest availability | ≥ 99.5% of `POST /log` requests succeed | 7 days |
| Ingest latency | p95 < 500 ms for `POST /log` | 1 day |
| Session query latency | p95 < 1 s for `GET /sessions` | 1 day |
| Dashboard stats latency | p95 < 800 ms for `GET /dashboard/stats` | 1 day |
| Auth latency | p95 < 300 ms for `POST /auth/login` | 1 day |
| Alert delivery delay | p95 WebSocket delivery < 2 s from event ingestion | 1 day |
| AI analysis latency | p95 < 10 s for `POST /ai/analyze` (LLM dependent) | 1 day |
| AI availability | `GET /ai/status` returns `available: true` ≥ 95% of time | 7 days |

:::note
The AI endpoints have a deliberately relaxed SLO (10 s, 95% availability) because they depend on an external LLM service. When the LLM is down, the platform degrades gracefully — ML-based scoring continues, but narrative triage is unavailable.
:::

---

## Logging Practices

### Log Format

All backend log entries are structured JSON:

```json
{
  "timestamp": "2024-01-15T10:22:33.456Z",
  "level": "INFO",
  "logger": "backend.routers.ingest",
  "request_id": "a1b2c3d4",
  "message": "Event ingested",
  "source_ip": "203.0.113.7",
  "sensor_id": "cowrie-1",
  "event_type": "login_attempt",
  "session_id": "uuid-...",
  "threat_score": 0.42,
  "threat_level": "medium",
  "duration_ms": 87
}
```

### Key Log Events to Monitor

| Event | Logger | What It Signals |
|---|---|---|
| `Event ingested` | `backend.routers.ingest` | Normal operation — volume metric |
| `Score computed` | `backend.services.threat_scorer` | Scoring pipeline healthy |
| `Alert queued` | `backend.services.alert_manager` | High/Critical event detected |
| `WebSocket broadcast` | `backend.routers.alerts` | Alert delivered to analysts |
| `Canary token triggered` | `backend.routers.canary` | High-confidence IoC |
| `Auth login success` | `backend.routers.auth` | Analyst logged in |
| `Auth login failed` | `backend.routers.auth` | Failed login — potential brute force |
| `Token refresh` | `backend.routers.auth` | Normal session extension |
| `LLM analysis complete` | `backend.services.llm_service` | AI triage cycle |
| `LLM unavailable` | `backend.services.llm_service` | LLM down — graceful degradation |
| `DB connection pool exhausted` | SQLAlchemy | Saturation — scale database pool |

### Log Levels

| Level | Used for |
|---|---|
| `DEBUG` | Verbose per-request details (disabled in production) |
| `INFO` | Normal operation milestones (ingest success, score computed, auth) |
| `WARNING` | Unusual but non-fatal conditions (LLM degraded mode, slow query) |
| `ERROR` | Handled failures (DB timeout, LLM API error) |
| `CRITICAL` | Unhandled exceptions, service startup failures |

Set `LOG_LEVEL=INFO` in production. Set `LOG_LEVEL=DEBUG` locally for troubleshooting.

---

## Alerting Model

Operational alerts (separate from threat alerts sent to analysts) notify operators when the platform itself is degrading:

| Alert | Condition | Severity |
|---|---|---|
| Ingest error surge | Error rate on `POST /log` > 5% for 5 minutes | High |
| Ingest latency breach | p95 > 1 s for 5 consecutive minutes | Medium |
| Database unreachable | `/health` returns `database: false` | Critical |
| LLM service down | `GET /ai/status` returns `available: false` for 15+ minutes | Low |
| Auth failure spike | > 20 failed logins in 60 seconds | Medium (possible brute force against platform) |
| Alert queue overflow | `alert_manager.queue_depth > 1000` | High |
| High memory usage | Container memory > 80% of limit | Medium |

:::warning
Auth failure spike alerts are operationally important. If attackers discover the API, they may try to brute-force platform credentials. The platform itself is a target.
:::

---

## Dashboard Views

### Splunk Dashboards (`splunk/dashboards/`)

The production Splunk integration provides:

| Dashboard | What It Shows |
|---|---|
| **Ingest Rate** | Events/minute over time, broken by `sensor_id` |
| **Threat Level Distribution** | Pie chart of Low/Medium/High/Critical sessions |
| **Top Attackers** | Top 20 source IPs by event count |
| **Alert Timeline** | High/Critical alerts over 24h |
| **Auth Activity** | Login success/failure rate, token refresh activity |
| **LLM Usage** | `analyze_session` call rate, average response latency |
| **Error Rate** | 4xx/5xx rate per endpoint |

### SOC Dashboard (Frontend)

The built-in dashboard (`/dashboard`) shows:
- 24-hour attack summary (total events, unique attackers, active sessions)
- Threat level timeline (sparkline per hour)
- Top attackers table
- Live alert feed (WebSocket)

---

## AI and Enrichment Metrics

| Metric | What It Measures |
|---|---|
| `ai.analyze_session.count` | Total calls to `POST /ai/analyze` |
| `ai.analyze_session.latency_ms` | End-to-end LLM round-trip time |
| `ai.chat.count` | Total chat turns on `POST /ai/chat` |
| `ai.unavailable.count` | Times `LLMService` returned `available: false` |
| `scoring.ml.count` | Times ML scorer ran (vs degraded mode) |
| `scoring.degraded.count` | Times rule-based fallback was used |

Track `ai.unavailable.count` alongside `ai.analyze_session.count` to understand what fraction of triage attempts succeeded.

---

## Weekly Health Review Checklist

Run this review every Monday before the week begins:

```bash
# Check for any error log spikes in the last 7 days
# (adapt to your log platform — example uses jq on saved log files)
cat backend_logs.jsonl | jq -r 'select(.level=="ERROR") | .message' | sort | uniq -c | sort -rn

# Check database health
curl -s http://localhost:8000/health | jq .

# Check AI status
curl -s http://localhost:8000/ai/status \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .

# Check alert queue depth (if metrics endpoint is enabled)
curl -s http://localhost:8000/health | jq '.alert_queue_depth'
```

Review the following:
- [ ] Average ingest latency — has it trended upward?
- [ ] Error rate — any new error types in the past week?
- [ ] Auth failure rate — any spikes suggesting brute-force attempts against the platform?
- [ ] LLM availability — what fraction of AI triage requests succeeded?
- [ ] Database connection pool hits — is the pool sized appropriately for the current event volume?
