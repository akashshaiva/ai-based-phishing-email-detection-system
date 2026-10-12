# PhishShield AI PowerShell Startup Script
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "          PHISHSHIELD AI - EMAIL PHISHING DETECTION SYSTEM           " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "`n[1/3] Verifying Python..." -ForegroundColor Yellow
python --version

Write-Host "`n[2/3] Verifying dependencies from requirements.txt..." -ForegroundColor Yellow
python -m pip install -r requirements.txt

Write-Host "`n[3/3] Launching PhishShield AI Server on http://127.0.0.1:8000..." -ForegroundColor Green
Start-Process "http://127.0.0.1:8000"

python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload
