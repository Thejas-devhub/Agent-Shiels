
@echo off
title AgentShield - AI Action Firewall
cd /d "%~dp0"

echo ==========================================
echo       AgentShield - DevHost 2026
echo ==========================================

echo Starting AgentShield Backend...
start "AgentShield Backend" cmd /k "cd /d %~dp0backend && python -m pip install -r requirements.txt && python main.py"

ping 127.0.0.1 -n 4 >nul

echo Starting AgentShield Frontend...
start "AgentShield Frontend" cmd /k "cd /d %~dp0frontend && npm install && npm run dev"

echo.
echo Backend API: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo Frontend: http://localhost:5173
echo.
pause

