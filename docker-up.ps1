# Build and start the full GovSys stack in Docker.
#   .\docker-up.ps1                  use the Ollama already running on this PC
#   .\docker-up.ps1 -OllamaInDocker  run Ollama in a container too (pulls phi3 + gemma3:270m, ~2.5 GB)
#   .\docker-up.ps1 -LocalLogin      use the built-in sign-in service instead of Keycloak
param([switch]$OllamaInDocker, [switch]$LocalLogin)
$ErrorActionPreference = "Continue"   # docker writes progress to stderr; we check $LASTEXITCODE instead
Set-Location $PSScriptRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or not on PATH. Install Docker Desktop, start it, then re-run."
}
docker info --format "{{.ServerVersion}}" *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker is installed but not running. Start Docker Desktop and wait until it says 'running'." }

# Local mode uses the same ports (5433, 8181, 5000, 8501) - stop it first.
if (Test-Path .venv\Scripts\python.exe) {
    Write-Host "==> Stopping local-mode services (if running) to free ports"
    .\.venv\Scripts\python scripts\services.py stop all | Out-Null
}

$profileArgs = @()
if ($OllamaInDocker) {
    $env:DOCKER_OLLAMA_URL = "http://ollama:11434"
    $profileArgs = @("--profile", "ollama")
} else {
    Remove-Item Env:DOCKER_OLLAMA_URL -ErrorAction SilentlyContinue
    try { Invoke-WebRequest http://127.0.0.1:11434/api/tags -UseBasicParsing -TimeoutSec 3 | Out-Null }
    catch { Write-Warning "Host Ollama not reachable on :11434 - answers will fall back to templates. Start Ollama or use -OllamaInDocker." }
}
if ($LocalLogin) { $env:DOCKER_IDENTITY_PROVIDER = "local" } else { Remove-Item Env:DOCKER_IDENTITY_PROVIDER -ErrorAction SilentlyContinue }

Write-Host "==> Building and starting containers (first run downloads ~3 GB and takes 5-15 minutes)"
docker compose @profileArgs up -d --build
if ($LASTEXITCODE -ne 0) { throw "docker compose up failed" }

Write-Host "==> Waiting for the app to finish bootstrapping"
$deadline = (Get-Date).AddMinutes(15)
do {
    Start-Sleep 5
    $state = docker inspect --format "{{.State.Health.Status}}" govsys-app-1 2>$null
    Write-Host "    app: $state"
    if ((docker inspect --format "{{.State.Status}}" govsys-app-1 2>$null) -eq "exited") {
        docker compose logs --tail 60 app
        throw "The app container exited - see the log above."
    }
} until ($state -eq "healthy" -or (Get-Date) -gt $deadline)
if ($state -ne "healthy") { docker compose logs --tail 60 app; throw "App did not become healthy in 15 minutes." }

Write-Host ""
Write-Host "GovSys is running in Docker:"
Write-Host "  Dashboard  http://localhost:8501   (alice / Alice@123, carol / Carol@123 ...)"
Write-Host "  Keycloak   http://localhost:8080   (admin / admin)"
Write-Host "  MLflow     http://localhost:5000"
Write-Host "  Langfuse   http://localhost:3000   (admin@govsys.local / govsys-admin)"
Write-Host "  OPA        http://localhost:8181"
Write-Host "Logs: docker compose logs -f app    Stop: .\docker-down.ps1"
