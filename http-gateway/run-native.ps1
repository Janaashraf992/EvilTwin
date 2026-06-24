# EvilTwin HTTP Gateway - Native Windows Runner
# Preserves real attacker IPs (no Docker NAT masking).
# Run as Administrator from the Eviltwin project root.

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " EvilTwin HTTP Gateway (Native Windows)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$ProjectRoot = Split-Path $PSScriptRoot -Parent
$EnvFile = Join-Path $ProjectRoot ".env"

# ---------- .env reader ----------
function Get-DotEnvValue {
    param([string]$Path, [string]$Key)
    if (-not (Test-Path $Path)) { return $null }
    $match = Select-String -Path $Path -Pattern "^\s*$([regex]::Escape($Key))\s*=" -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $match) { return $null }
    $val = ($match.Line -split "=", 2)[1].Trim()
    return $val.Trim('"').Trim("'")
}

# ---------- install dependencies ----------
$pkgs = @("aiohttp")
foreach ($p in $pkgs) {
    $installed = pip show $p 2>$null
    if (-not $installed) {
        Write-Host "Installing $p..." -ForegroundColor Yellow
        pip install $p
    }
}

# ---------- config ----------
# The host process reaches the still-Dockerized services through their
# published localhost ports (see docker-compose.yml).
$env:ROUTING_BACKEND_URL = if ($env:ROUTING_BACKEND_URL) { $env:ROUTING_BACKEND_URL } else { "http://localhost:8000" }
$env:INGEST_BACKEND_URL  = if ($env:INGEST_BACKEND_URL)  { $env:INGEST_BACKEND_URL  } else { "http://localhost:8000" }
$env:REAL_HTTP_URL       = if ($env:REAL_HTTP_URL)       { $env:REAL_HTTP_URL       } else { "http://localhost:8088" }
$env:HTTP_GATEWAY_PORT   = if ($env:HTTP_GATEWAY_PORT)   { $env:HTTP_GATEWAY_PORT   } else { "8888" }

# Pull secrets/creds from .env so the native gateway agrees with the
# Dockerized backend (routing key) and stays consistent across restarts.
$routingKey = Get-DotEnvValue $EnvFile "ROUTING_API_KEY"
$secretKey  = Get-DotEnvValue $EnvFile "SECRET_KEY"
$realUser   = Get-DotEnvValue $EnvFile "REAL_HTTP_USER"
$realPass   = Get-DotEnvValue $EnvFile "REAL_HTTP_PASSWORD"

if ($routingKey) { $env:ROUTING_API_KEY    = $routingKey }
if ($secretKey)  { $env:SECRET_KEY         = $secretKey }
$env:REAL_HTTP_USER     = if ($realUser) { $realUser } elseif ($env:REAL_HTTP_USER) { $env:REAL_HTTP_USER } else { "real" }
$env:REAL_HTTP_PASSWORD = if ($realPass) { $realPass } elseif ($env:REAL_HTTP_PASSWORD) { $env:REAL_HTTP_PASSWORD } else { "eviltwin" }

# ---------- firewall ----------
Write-Host "Opening Windows Firewall port $($env:HTTP_GATEWAY_PORT)..." -ForegroundColor Yellow
try {
    New-NetFirewallRule -DisplayName "EvilTwin HTTP Gateway" -Direction Inbound -Protocol TCP -LocalPort $env:HTTP_GATEWAY_PORT -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Firewall rule created." -ForegroundColor Green
} catch {
    Write-Host "Firewall rule may already exist or permission denied." -ForegroundColor DarkYellow
}

# ---------- stop Docker http-gateway to free the port ----------
Write-Host "Stopping Docker http-gateway container to free port $($env:HTTP_GATEWAY_PORT)..." -ForegroundColor Yellow
docker stop eviltwin-http-gw 2>$null
docker rm -f eviltwin-http-gw 2>$null

# ---------- run ----------
Write-Host ""
Write-Host "Backend:  $($env:ROUTING_BACKEND_URL)" -ForegroundColor Green
Write-Host "Real:     $($env:REAL_HTTP_URL) (credential-gated, hidden by default)" -ForegroundColor Green
Write-Host "Gate user: $($env:REAL_HTTP_USER)" -ForegroundColor Green
Write-Host "Listening on port $($env:HTTP_GATEWAY_PORT) - real LAN IPs preserved." -ForegroundColor Green
Write-Host ""

Set-Location $PSScriptRoot
python -u proxy.py
