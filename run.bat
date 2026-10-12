@echo off
title PhishShield AI - Phishing Detection System
echo =====================================================================
echo           PHISHSHIELD AI - EMAIL PHISHING DETECTION SYSTEM
echo =====================================================================
echo.

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in PATH. Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

echo [2/3] Installing / Verifying dependencies from requirements.txt...
python -m pip install -r requirements.txt

echo.
echo [3/3] Starting PhishShield AI Server...
echo Web Dashboard URL: http://127.0.0.1:8000
echo API Documentation: http://127.0.0.1:8000/docs
echo.

start "" http://127.0.0.1:8000
python -m uvicorn main:app --host 127.0.0.1 --port 8000 --app-dir backend --reload

pause
