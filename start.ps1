# Start the local stack: Postgres, OPA, MLflow UI, Streamlit dashboard.
Set-Location $PSScriptRoot
.\.venv\Scripts\python scripts\services.py start all
Write-Host "`nDashboard : http://localhost:8501"
Write-Host "MLflow UI : http://127.0.0.1:5000"
Write-Host "OPA       : http://127.0.0.1:8181"
Write-Host "Stop with .\stop.ps1"
