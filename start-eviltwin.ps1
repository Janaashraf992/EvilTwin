# EvilTwin - single start command (Docker stack + native real-IP gateways).
# Run this INSTEAD of `docker compose up`. Real LAN attacker IPs are preserved.
param([switch]$Build)

$ErrorActionPreference = "Stop"

# ---- self-elevate (needed for firewall + binding port 22) ----
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $argList = @("-NoExit","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"")
    if ($Build) { $argList += "-Build" }
    Start-Process powershell -Verb RunAs -ArgumentList $argList
    exit
}

Set-Location $PSScriptRoot

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " EvilTwin - starting (real IPs enabled)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# ---- Docker stack (gateway + http-gateway excluded via profile) ----
Write-Host "Starting Docker stack..." -ForegroundColor Yellow
if ($Build) { docker compose up -d --build } else { docker compose up -d }

# ---- free ports 22 / 8888 from any pre-existing Docker gateway containers ----
docker rm -f eviltwin-gateway 2>$null | Out-Null
docker rm -f eviltwin-http-gw 2>$null | Out-Null

# ---- launch native gateways (each in its own admin window) ----
$ssh  = Join-Path $PSScriptRoot "gateway\run-native.ps1"
$http = Join-Path $PSScriptRoot "http-gateway\run-native.ps1"

Write-Host "Launching native SSH gateway (port 22)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","`"$ssh`""

Write-Host "Launching native HTTP gateway (port 8888)..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit","-ExecutionPolicy","Bypass","-File","`"$http`""

$lan = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -like "192.168.*" } |
        Select-Object -First 1).IPAddress

Write-Host ""
Write-Host "All up. Real attacker IPs are now captured on:" -ForegroundColor Green
Write-Host "  SSH  : $lan`:22"   -ForegroundColor Green
Write-Host "  HTTP : $lan`:8888" -ForegroundColor Green
Write-Host "Dashboard: http://localhost:3000" -ForegroundColor Green
Write-Host "Keep the two gateway windows open while the demo runs." -ForegroundColor DarkYellow
