#!/usr/bin/env bash
# Evidence Sanitisation Gateway — startup script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Evidence Sanitisation Gateway  v1.0    ║"
echo "  ║   LOCAL ONLY · NO TELEMETRY · ENCRYPTED  ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# Install deps if needed
if ! python3 -c "import fastapi, cryptography" 2>/dev/null; then
  echo "  Installing dependencies..."
  pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages -q
fi

# Create data dir inside backend/ with restricted permissions
mkdir -p "$SCRIPT_DIR/backend/data"
chmod 700 "$SCRIPT_DIR/backend/data"

echo "  Starting server on http://127.0.0.1:8000"
echo "  Press Ctrl+C to stop."
echo ""

cd "$SCRIPT_DIR/backend"
python3 -m uvicorn main:app --host 127.0.0.1 --port 8000 --log-level warning
