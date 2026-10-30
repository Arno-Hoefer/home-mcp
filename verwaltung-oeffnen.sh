#!/usr/bin/env bash
# Verwaltungsseite von home-mcp vom Mac aus öffnen: SSH-Tunnel im Hintergrund + Browser auf http://127.0.0.1:8791.
# Aufruf:  ./verwaltung-oeffnen.sh [ssh-host]      (Standard: raspi, oder Umgebungsvariable HOME_MCP_SSH)
# Die Seite lauscht auf dem Pi nur auf 127.0.0.1:8791 – ohne Tunnel kommt man nicht hin, und das ist Absicht.
# Immer 127.0.0.1 statt „localhost“ benutzen: Google leitet nach der Anmeldung genau dorthin zurück.
set -euo pipefail

HOST="${1:-${HOME_MCP_SSH:-raspi}}"
PORT=8791
URL="http://127.0.0.1:$PORT"

lauscht() { lsof -nP -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; }

if lauscht; then
  echo "Port $PORT lauscht schon – Tunnel (oder etwas anderes) läuft bereits, baue keinen neuen auf."
else
  echo "Baue SSH-Tunnel zu $HOST auf (lokal $PORT → Pi 127.0.0.1:$PORT) …"
  ssh -f -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -L "$PORT:127.0.0.1:$PORT" "$HOST"
  for _ in 1 2 3 4 5 6 7 8 9 10; do lauscht && break; sleep 0.3; done
  lauscht || { echo "Tunnel steht nicht – ssh $HOST prüfen." >&2; exit 1; }
fi

if curl -fsS -o /dev/null --max-time 5 "$URL/" 2>/dev/null; then
  echo "Verwaltung antwortet ✓"
else
  echo "Hinweis: $URL antwortet (noch) nicht – läuft home-mcp? ssh $HOST systemctl status home-mcp" >&2
fi

if open -Ra "Google Chrome" 2>/dev/null; then
  open -a "Google Chrome" "$URL"
else
  open "$URL"
fi

cat <<EOF

Geöffnet: $URL
Tunnel wieder schließen:
  pkill -f "ssh -f -N -o ExitOnForwardFailure=yes .*-L $PORT:127.0.0.1:$PORT"
  (oder: lsof -nP -iTCP:$PORT -sTCP:LISTEN  → PID ablesen → kill <PID>)
EOF
