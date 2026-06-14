# EvilTwin Validation Command Log

Date: 2026-04-28

This file records the shell commands and browser actions used during the Fedora-to-Windows EvilTwin validation session.

Scope:

- Fedora client host: `10.215.72.228`
- Windows EvilTwin host: `10.215.72.43`
- Frontend: `http://10.215.72.43:3000`
- Backend: `http://10.215.72.43:8000`
- Only safe, non-destructive validation traffic was generated.
- Live JWTs are redacted and shown as placeholders.

## 1. Reachability And Service Checks

Backend health:

```bash
curl -sS -m 5 -i http://10.215.72.43:8000/health
```

Frontend root page:

```bash
curl -sS -m 5 -i http://10.215.72.43:3000/ | sed -n '1,40p'
```

Dionaea HTTP surface:

```bash
curl -sS -m 5 -i http://10.215.72.43:8081/ | sed -n '1,30p'
```

FTP honeypot probe:

```bash
printf 'QUIT\r\n' | nc -nv -w 5 10.215.72.43 2121
```

SSH honeypot TCP reachability:

```bash
printf '' | nc -nv -w 5 10.215.72.43 2222
```

Local-backend disambiguation on Fedora:

```bash
curl -sS -m 5 -i http://localhost:8000/health
```

## 2. Frontend Runtime Target Checks

Demo login directly against backend:

```bash
curl -sS -m 5 -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo'
```

Inspect built frontend bundle for API and WebSocket targets:

```bash
curl -sS -m 5 http://10.215.72.43:3000/assets/index-CDYycYh1.js \
  | grep -o 'localhost:8000\|ws://localhost:8000/ws/alerts\|http://10\.215\.72\.43:8000\|ws://10\.215\.72\.43:8000/ws/alerts' \
  | head
```

## 3. CORS And Auth Header Checks

Check login response headers for browser-origin requests:

```bash
curl -sS -i -X POST http://10.215.72.43:8000/auth/login \
  -H 'Origin: http://10.215.72.43:3000' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | sed -n '1,20p'
```

Fetch current authenticated user using a bearer token:

```bash
curl -sS http://10.215.72.43:8000/auth/me \
  -H 'Authorization: Bearer <ACCESS_TOKEN>'
```

## 4. Host And Session Baseline Checks

Get Fedora LAN IPs:

```bash
hostname -I
```

Try filtered sessions for Fedora source IP:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS "http://10.215.72.43:8000/sessions?ip=10.215.72.228&page_size=25" \
  -H "Authorization: Bearer $TOKEN"
```

Read dashboard stats baseline:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS http://10.215.72.43:8000/stats \
  -H "Authorization: Bearer $TOKEN"
```

Read unfiltered recent sessions baseline:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS "http://10.215.72.43:8000/sessions?page_size=25" \
  -H "Authorization: Bearer $TOKEN"
```

## 5. Safe Ingest Route Validation

Check that `/log` exists in the deployed OpenAPI schema:

```bash
curl -sS http://10.215.72.43:8000/openapi.json | grep -o '"/log"' | head -n 1
```

Benign Cowrie-shaped event:

```bash
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SID=$(cut -d- -f1 /proc/sys/kernel/random/uuid)

curl -sS -m 5 -i -X POST http://10.215.72.43:8000/log \
  -H 'Content-Type: application/json' \
  -d "{\"eventid\":\"cowrie.command.input\",\"src_ip\":\"10.215.72.228\",\"src_port\":45678,\"dst_ip\":\"10.215.72.43\",\"dst_port\":22,\"session\":\"$SID\",\"protocol\":\"ssh\",\"timestamp\":\"$TS\",\"message\":\"benign validation event\",\"input\":\"echo health-check\"}"
```

Read sessions after benign Cowrie ingest:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS http://10.215.72.43:8000/sessions?page_size=50 \
  -H "Authorization: Bearer $TOKEN"
```

Read stats after benign Cowrie ingest:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS http://10.215.72.43:8000/stats \
  -H "Authorization: Bearer $TOKEN"
```

Benign Dionaea-shaped event:

```bash
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SID=$(cut -d- -f1 /proc/sys/kernel/random/uuid)

curl -sS -m 5 -i -X POST http://10.215.72.43:8000/log \
  -H 'Content-Type: application/json' \
  -d "{\"eventid\":\"dionaea.http.request\",\"src_ip\":\"10.215.72.228\",\"src_port\":45679,\"dst_ip\":\"10.215.72.43\",\"dst_port\":80,\"session\":\"$SID\",\"protocol\":\"http\",\"timestamp\":\"$TS\",\"message\":\"GET /status\"}"
```

Read sessions after benign Dionaea ingest:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS http://10.215.72.43:8000/sessions?page_size=50 \
  -H "Authorization: Bearer $TOKEN"
```

Read stats after benign Dionaea ingest:

```bash
TOKEN=$(curl -sS -X POST http://10.215.72.43:8000/auth/login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'username=analyst%40eviltwin.local&password=eviltwin-demo' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -sS http://10.215.72.43:8000/stats \
  -H "Authorization: Bearer $TOKEN"
```

## 6. Frontend Build And Diagnostics

Frontend production build:

```bash
cd /home/ahmed/Dev/EvilTwin/frontend && npm run build
```

TypeScript project build:

```bash
npx tsc -b && echo __TSC_OK__
```

Compiler-only TypeScript check:

```bash
timeout 30s npx tsc -p /home/ahmed/Dev/EvilTwin/frontend/tsconfig.json --noEmit; printf '__TSC_STATUS=%s\n' "$?"
```

Inspect build log state:

```bash
pwd && ls -l /tmp/eviltwin-frontend-build.log && tail -n 40 /tmp/eviltwin-frontend-build.log
```

Inspect full saved build log:

```bash
wc -l /tmp/eviltwin-frontend-build.log && sed -n '1,80p' /tmp/eviltwin-frontend-build.log
```

Check active Vite or TypeScript processes:

```bash
ps -ef | grep -E 'vite|tsc' | grep -v grep
```

## 7. Browser Actions

These were not shell commands, but they were part of the validation flow:

1. Opened `http://10.215.72.43:3000/` from the Fedora browser.
2. Logged in with the demo analyst account when the deployment allowed it.
3. Reloaded `/dashboard` to confirm session counters and top-attacker entries changed.
4. Opened `/sessions` to confirm the Cowrie and Dionaea records appeared in the list.
5. Clicked the latest session row to verify the detail pane showed the recorded honeypot, protocol, IP, and threat score.

## 8. Key Outcomes

- Backend and frontend were reachable over the LAN.
- The frontend host-derivation fix was confirmed.
- Safe Cowrie- and Dionaea-shaped events were accepted by `/log`.
- Dashboard counters increased from `0` to `2` sessions after benign ingest.
- The sessions view displayed the Fedora-origin records.
- `GET /sessions?ip=10.215.72.228...` returned `500` even though unfiltered `/sessions` worked.
- Direct `http://10.215.72.43:8081/` probing still returned an empty reply.
