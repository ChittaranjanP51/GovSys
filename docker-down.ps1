# Stop the Docker stack.  -Wipe also deletes all data volumes (database, audit log, registry, traces).
param([switch]$Wipe)
Set-Location $PSScriptRoot
if ($Wipe) {
    $answer = Read-Host "This permanently deletes the Docker database, audit log, model registry and traces. Type WIPE to confirm"
    if ($answer -ne "WIPE") { Write-Host "Cancelled."; exit 1 }
    docker compose --profile ollama down -v
} else {
    docker compose --profile ollama down
}
