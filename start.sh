#!/bin/bash
echo "============================================================"
echo "  AgentShield: AI Action Firewall — DevHost 2026"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/2] Starting AgentShield Backend (FastAPI on port 8000)..."
(cd "$SCRIPT_DIR/backend" && python3 main.py) &
BACKEND_PID=$!

sleep 2

echo "[2/2] Starting AgentShield Frontend (Vite on port 5173)..."
(cd "$SCRIPT_DIR/frontend" && npm run dev) &
FRONTEND_PID=$!

echo ""
echo "============================================================"
echo "  AgentShield is running!"
echo "  - Backend API: http://localhost:8000 (Docs: http://localhost:8000/docs)"
echo "  - Web Console: http://localhost:5173"
echo "  Press Ctrl+C to shut down both services."
echo "============================================================"

trap "kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit" SIGINT SIGTERM
wait
