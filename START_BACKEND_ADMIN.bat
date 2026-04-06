@echo off
:: ============================================================
::  AI SOC Platform — Start Backend as Administrator
::  Double-click this file to auto-elevate and start the server
:: ============================================================

:: If not already admin, relaunch as admin
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:: We are admin — activate venv and start uvicorn
cd /d "C:\Users\User\Desktop\Github\AI Threat Detection System\backend"
call "C:\Users\User\Desktop\Github\venv\Scripts\activate.bat"

echo.
echo  =====================================================
echo   AI SOC Platform Backend  ^|  Running as Admin
echo   http://localhost:8000
echo   Press Ctrl+C to stop
echo  =====================================================
echo.

uvicorn app.main:app --reload --port 8000

pause
