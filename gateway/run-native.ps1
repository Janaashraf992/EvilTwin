# EvilTwin Gateway — Native Windows Runner
# Preserves real attacker IPs (no Docker NAT masking).
# Run as Administrator from the Eviltwin project root.

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " EvilTwin SSH Gateway (Native Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ---------- install dependencies ----------
$pkgs = @("asyncssh", "aiohttp")
foreach ($p in $pkgs) {
    $installed = pip show $p 2>$null
    if (-not $installed) {
        Write-Host "Installing $p..." -ForegroundColor Yellow
        pip install $p
    }
}

# ---------- config ----------
$env:BACKEND_URL       = if ($env:BACKEND_URL)       { $env:BACKEND_URL       } else { "http://localhost:8000" }
$env:REAL_SSH_HOST     = if ($env:REAL_SSH_HOST)     { $env:REAL_SSH_HOST     } else { "127.0.0.1" }
$env:REAL_SSH_PORT     = if ($env:REAL_SSH_PORT)     { $env:REAL_SSH_PORT     } else { "8022" }
$env:REAL_SSH_USER     = if ($env:REAL_SSH_USER)     { $env:REAL_SSH_USER     } else { "real" }
$env:REAL_SSH_PASSWORD = if ($env:REAL_SSH_PASSWORD) { $env:REAL_SSH_PASSWORD } else { "eviltwin" }
$env:HONEYPOT_HOST     = if ($env:HONEYPOT_HOST)     { $env:HONEYPOT_HOST     } else { "127.0.0.1" }
$env:HONEYPOT_PORT     = if ($env:HONEYPOT_PORT)     { $env:HONEYPOT_PORT     } else { "2222" }
$env:GATEWAY_LISTEN_PORT = "22"
$env:HOST_KEY_PATH     = Join-Path $PSScriptRoot "ssh_host_rsa_key"

# ---------- firewall ----------
Write-Host "Opening Windows Firewall port 22..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "EvilTwin Gateway" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow -Profile Any -ErrorAction SilentlyContinue
    Write-Host "Firewall rule created." -ForegroundColor Green
} catch {
    Write-Host "Firewall rule may already exist or permission denied." -ForegroundColor DarkYellow
}

# ---------- generate host key if missing ----------
if (-not (Test-Path $env:HOST_KEY_PATH)) {
    Write-Host "Generating SSH host key..." -ForegroundColor Yellow
    New-Item -ItemType Directory -Path (Split-Path $env:HOST_KEY_PATH) -Force | Out-Null
    python -c "from asyncssh import generate_private_key; k=generate_private_key('ssh-rsa',comment='eviltwin-gateway'); k.write_private_key(r'$env:HOST_KEY_PATH')"
}

# ---------- stop Docker gateway to free port 22 ----------
Write-Host "Stopping Docker gateway container to free port 22..." -ForegroundColor Yellow
docker stop eviltwin-gateway 2>$null
docker rm -f eviltwin-gateway 2>$null

# ---------- run ----------
Write-Host ""
Write-Host "Gateway: $($env:BACKEND_URL)" -ForegroundColor Green
Write-Host "Real:    $($env:REAL_SSH_USER)@$($env:REAL_SSH_HOST):$($env:REAL_SSH_PORT)" -ForegroundColor Green
Write-Host "Honeypot: $($env:HONEYPOT_HOST):$($env:HONEYPOT_PORT)" -ForegroundColor Green
Write-Host "Listening on port 22..." -ForegroundColor Green
Write-Host ""

Set-Location $PSScriptRoot
python -u gateway.py
