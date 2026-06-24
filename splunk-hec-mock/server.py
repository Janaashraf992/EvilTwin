from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler

EVENTS_FILE = os.environ.get("EVENTS_FILE", "/data/events.json")
HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "be411c42-caf0-49f8-9ffe-cae1be99e0d9")

_events: list[dict] = []
_lock = threading.Lock()
_request_count = 0
_error_count = 0


def _load_events():
    global _events
    if os.path.exists(EVENTS_FILE):
        try:
            with open(EVENTS_FILE, "r") as f:
                _events = json.load(f)
        except Exception:
            _events = []


def _save_events():
    with open(EVENTS_FILE, "w") as f:
        json.dump(_events[-5000:], f, indent=2)


_load_events()


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Splunk HEC - Event Viewer</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',monospace;background:#0d1117;color:#c9d1d9;padding:20px}
.header{display:flex;align-items:center;gap:16px;margin-bottom:20px;border-bottom:1px solid #30363d;padding-bottom:16px}
.header h1{font-size:20px;color:#58a6ff}
.stats{display:flex;gap:20px;margin-bottom:20px}
.stat{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;min-width:120px;text-align:center}
.stat .num{font-size:28px;font-weight:bold;color:#58a6ff}
.stat .label{font-size:11px;color:#8b949e;text-transform:uppercase;margin-top:4px}
.filters{margin-bottom:16px;display:flex;gap:8px}
.filters input,.filters select{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:8px 12px;border-radius:6px;font-size:13px}
.filters input{width:200px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;background:#161b22;border-bottom:2px solid #30363d;color:#8b949e;font-size:11px;text-transform:uppercase;position:sticky;top:0}
td{padding:8px 12px;border-bottom:1px solid #21262d;vertical-align:top}
tr:hover{background:#161b22}
.ip{color:#f0883e;font-family:monospace;font-weight:600}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600}
.badge-cowrie{background:#1f3a5f;color:#58a6ff}
.badge-dionaea{background:#3b1f2b;color:#f97583}
.badge-canary{background:#2d1f0f;color:#e3b341}
.badge-sync{background:#1f3a2b;color:#56d364}
.cmd{color:#79c0ff;font-family:monospace;font-size:12px}
.ts{color:#8b949e;font-size:11px;white-space:nowrap}
.empty{text-align:center;padding:40px;color:#8b949e}
.auto-refresh{color:#8b949e;font-size:11px}
</style>
</head>
<body>
<div class="header">
<h1>Splunk HEC Event Viewer</h1>
<span class="auto-refresh">Auto-refresh: 5s</span>
</div>
<div class="stats">
<div class="stat"><div class="num" id="total">0</div><div class="label">Total Events</div></div>
<div class="stat"><div class="num" id="received">0</div><div class="label">Received</div></div>
<div class="stat"><div class="num" id="errors">0</div><div class="label">Errors</div></div>
</div>
<div class="filters">
<input type="text" id="search" placeholder="Search IP / command..." oninput="render()">
<select id="source-filter" onchange="render()"><option value="">All Sources</option></select>
</div>
<div id="content"></div>
<script>
let allEvents=[];
function render(){
const q=document.getElementById("search").value.toLowerCase();
const sf=document.getElementById("source-filter").value;
let filtered=allEvents.filter(e=>{
if(sf&&e.source!==sf)return false;
if(!q)return true;
const d=JSON.stringify(e.data||{}).toLowerCase();
return d.includes(q)||String(e.source).toLowerCase().includes(q);
});
const html=filtered.length?`<table><thead><tr><th>Time</th><th>Source</th><th>IP</th><th>Honeypot</th><th>Protocol</th><th>Command</th></tr></thead><tbody>${filtered.map(e=>{
const d=e.data||{};
const cmds=Array.isArray(d.commands)?d.commands:[];
const lastCmd=cmds.length?cmds[cmds.length-1].command:"";
const badgeClass=e.source.includes("sync")?"badge-sync":d.honeypot==="cowrie"?"badge-cowrie":"badge-dionaea";
return`<tr><td class="ts">${e.timestamp?new Date(e.timestamp).toLocaleString():""}</td><td><span class="badge ${badgeClass}">${e.source}</span></td><td class="ip">${d.attacker_ip||""}</td><td>${d.honeypot||""}</td><td>${d.protocol||""}</td><td class="cmd">${lastCmd.slice(0,80)}</td></tr>`;
}).join("")}</tbody></table>`:`<div class="empty">No events found</div>`;
document.getElementById("content").innerHTML=html;
}
async function refresh(){
try{
const r=await fetch("/api/events");
const j=await r.json();
allEvents=j.events||[];
document.getElementById("total").textContent=j.count||0;
document.getElementById("received").textContent=j.request_count||0;
document.getElementById("errors").textContent=j.error_count||0;
const sources=[...new Set(allEvents.map(e=>e.source))];
const sel=document.getElementById("source-filter");
const cur=sel.value;
sel.innerHTML='<option value="">All Sources</option>'+sources.map(s=>`<option value="${s}"${s===cur?" selected":""}>${s}</option>`).join("");
render();
}catch(e){}
}
refresh();
setInterval(refresh,5000);
</script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass

    def _send_json(self, code: int, body: dict | list):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def _send_html(self, code: int, html: str):
        data = html.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        global _request_count
        _request_count += 1

        if self.path == "/" or self.path == "/dashboard":
            self._send_html(200, DASHBOARD_HTML)
            return

        if self.path.startswith("/api/events") or self.path.startswith("/events"):
            limit = 200
            with _lock:
                recent = list(_events[-limit:])
            body = {
                "count": len(_events),
                "request_count": _request_count,
                "error_count": _error_count,
                "events": recent,
            }
            self._send_json(200, body)
            return

        if self.path == "/health":
            self._send_json(200, {"status": "ok", "events": len(_events)})
            return

        self._send_json(404, {"error": "not found"})

    def _parse_qs(self):
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        return parse_qs(parsed.query)

    def _handle_hec_post(self):
        global _request_count, _error_count
        _request_count += 1

        path = self.path.split("?")[0]

        auth = self.headers.get("Authorization", "")
        expected = f"Splunk {HEC_TOKEN}"
        if auth != expected:
            _error_count += 1
            self._send_json(403, {"text": "Invalid token", "code": 1})
            return True

        try:
            length = int(self.headers.get("Content-Length", 0))
            body_raw = self.rfile.read(length)
            body = json.loads(body_raw)
        except Exception:
            _error_count += 1
            self._send_json(400, {"text": "Invalid JSON", "code": 1})
            return True

        if path == "/services/collector/raw":
            qs = self._parse_qs()
            source = qs.get("source", ["unknown"])[0]
            sourcetype = qs.get("sourcetype", ["unknown"])[0]
            index = qs.get("index", ["main"])[0]
            event = body if isinstance(body, dict) else {"raw": body_raw}
        else:
            event = body.get("event", body)
            source = body.get("source", "unknown")
            sourcetype = body.get("sourcetype", "unknown")
            index = body.get("index", "main")

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": source,
            "sourcetype": sourcetype,
            "index": index,
            "data": event,
        }

        with _lock:
            _events.append(record)
            if len(_events) > 5000:
                del _events[:-5000]

        if len(_events) % 10 == 0:
            _save_events()

        self._send_json(200, {"text": "Success", "code": 0})
        return True

    def do_POST(self):
        path = self.path.split("?")[0]
        if path in ("/services/collector/event", "/services/collector/raw"):
            self._handle_hec_post()
        else:
            global _request_count
            _request_count += 1
            self._send_json(404, {"text": "Not found", "code": 1})


def main():
    port = int(os.environ.get("PORT", "8088"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Splunk HEC Mock listening on :{port}")
    print(f"Token: {HEC_TOKEN[:20]}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _save_events()
        server.server_close()


if __name__ == "__main__":
    main()
