#!/usr/bin/env bash
# Installiert/aktualisiert home-mcp auf dem Pi. Aufruf: sudo bash install.sh
# Schlüssel für Claude Code (Tailnet) anzeigen: sudo cat /srv/home-mcp/token
set -euo pipefail
cd "$(dirname "$0")"
command -v psql >/dev/null || { apt-get update -qq && apt-get install -y postgresql-client; }
command -v curl >/dev/null || apt-get install -y curl
id homemcp >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin homemcp
install -d -o homemcp -g homemcp -m 700 /srv/home-mcp /srv/home-mcp/konten
install -d -m 755 /opt/home-mcp
install -m 644 home_mcp.py nutzer.py freigaben.py verwaltung.py einrichten.py /opt/home-mcp/
# HOME_MCP_PUBLIC = Tailscale-Name dieses Rechners – muss genau der Funnel-Adresse entsprechen, darum nicht von Hand
NAME=$(tailscale status --json 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null || true)
case "$NAME" in *.ts.net) ;; *) echo "Tailscale ist nicht angemeldet oder MagicDNS ist aus – zuerst: sudo tailscale up"; exit 1 ;; esac
sed "s|^Environment=HOME_MCP_PUBLIC=.*|Environment=HOME_MCP_PUBLIC=https://$NAME|" home-mcp.service > /etc/systemd/system/home-mcp.service
chmod 644 /etc/systemd/system/home-mcp.service
echo "Öffentliche Adresse: https://$NAME"
if [ -f /tmp/home-mcp-client.json ]; then
  install -o homemcp -g homemcp -m 600 /tmp/home-mcp-client.json /srv/home-mcp/client.json && shred -u /tmp/home-mcp-client.json
fi
if [ ! -s /srv/home-mcp/token ]; then
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' > /srv/home-mcp/token
fi
chown homemcp:homemcp /srv/home-mcp/token; chmod 600 /srv/home-mcp/token
systemctl daemon-reload
systemctl enable --now home-mcp.service
systemctl restart home-mcp.service
sleep 2
systemctl is-active home-mcp.service
curl -fsS http://127.0.0.1:8790/ping; echo
# Öffentlich nur dieser Dienst, über Tailscale Funnel auf HTTPS 443 – Claudes Connector-Dienst erreicht nur den Standardport.
# Der Echo-Bot liegt deshalb auf 8443 (nur im Tailnet).
if timeout 20 tailscale funnel --bg --https=443 http://127.0.0.1:8790 >/tmp/home-mcp-funnel.log 2>&1; then
  tailscale funnel status
else
  echo "Funnel noch nicht erlaubt – Link aus der Meldung im Browser öffnen (Tailscale-Admin), dann install.sh erneut:"
  head -5 /tmp/home-mcp-funnel.log
fi
