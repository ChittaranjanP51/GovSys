# One-time local setup (Windows, no Docker). Safe to re-run.
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$ProgressPreference = "SilentlyContinue"

if (-not (Test-Path .venv)) {
    Write-Host "==> Creating virtual environment (.venv, Python 3.13)"
    py -3.13 -m venv .venv
}
Write-Host "==> Installing Python dependencies"
.\.venv\Scripts\python -m pip install --upgrade pip -q
.\.venv\Scripts\python -m pip install -r requirements.txt -q

New-Item -ItemType Directory -Force bin | Out-Null
if (-not (Test-Path bin\opa.exe)) {
    Write-Host "==> Downloading Open Policy Agent"
    Invoke-WebRequest https://openpolicyagent.org/downloads/latest/opa_windows_amd64.exe -OutFile bin\opa.exe
}
if (-not (Test-Path bin\pgsql\bin\pg_ctl.exe)) {
    Write-Host "==> Downloading portable PostgreSQL 17 (~330 MB)"
    Invoke-WebRequest https://get.enterprisedb.com/postgresql/postgresql-17.6-1-windows-x64-binaries.zip -OutFile bin\pg.zip
    Expand-Archive bin\pg.zip -DestinationPath bin -Force
    Remove-Item bin\pg.zip
}

Write-Host "==> Checking Ollama models"
foreach ($m in @("phi3:latest", "gemma3:270m")) {
    if (-not ((ollama list) -match [regex]::Escape($m))) { ollama pull $m }
}

.\.venv\Scripts\python scripts\bootstrap.py
Write-Host "`nSetup complete. Run .\start.ps1"
