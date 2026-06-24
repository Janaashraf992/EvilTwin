"""
Dummy Real HTTP Server — shows "You are a normal user" web page
for "real" decisions. Attacker sees this when browsing to the IP.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime
from zoneinfo import ZoneInfo
import os

CAIRO_TZ = ZoneInfo("Africa/Cairo")

HTTP_PORT = int(os.getenv("HTTP_PORT", "8080"))

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authenticated — Real Network</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #0f2027, #203a43, #2c5364);
            color: #e0e0e0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(46,204,113,0.3);
            border-radius: 12px;
            padding: 40px 50px;
            max-width: 520px;
            text-align: center;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        .icon { font-size: 48px; margin-bottom: 15px; }
        h1 { color: #2ecc71; font-size: 24px; margin-bottom: 10px; }
        .badge {
            display: inline-block;
            background: rgba(46,204,113,0.15);
            color: #2ecc71;
            border: 1px solid #2ecc71;
            border-radius: 20px;
            padding: 5px 18px;
            font-size: 14px;
            margin: 12px 0 20px;
        }
        p { color: #aaa; font-size: 14px; line-height: 1.6; margin-bottom: 8px; }
        hr { border: none; border-top: 1px solid rgba(255,255,255,0.1); margin: 20px 0; }
        .footer { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">&#x1f510;</div>
        <h1>Welcome</h1>
        <div class="badge">AUTHENTICATED</div>
        <p>You are connected as a <strong>normal user</strong> on the real network.</p>
        <p>No security alerts have been triggered.</p>
        <p>Your connection has been verified as legitimate.</p>
        <hr>
        <p class="footer">Ubuntu 22.04.2 LTS (GNU/Linux 5.15.0-91-generic x86_64)</p>
        <p class="footer">IPv4: 10.0.1.100 | Load: 0.08 | Uptime: 30 days</p>
        <p class="footer">Connection accepted at """ + datetime.now(CAIRO_TZ).strftime("%H:%M:%S") + """</p>
    </div>
</body>
</html>"""


class RealHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self._respond()

    def do_POST(self):
        self._respond()

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def _respond(self):
        body = HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # silent


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", HTTP_PORT), RealHandler)
    print(f"Dummy Real HTTP Server running on port {HTTP_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
