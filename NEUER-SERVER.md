# Neuer Server mit home-mcp und NookBot – Teil 1: home-mcp

Für jemanden, der **auf einem eigenen, leeren Server** home-mcp und danach NookBot betreiben will – mit eigenen Konten,
ohne etwas von einer bestehenden Installation zu übernehmen.

**Reihenfolge: erst home-mcp (diese Datei), dann NookBot** (`docs/neuer-server.md` im Repo
**nookbot**). NookBot braucht beim Einrichten einen Bot-Schlüssel aus home-mcp und
läuft ohne home-mcp nur ohne Mail, Kalender, Drive und Freigaben.

Platzhalter: `server` = SSH-Alias des neuen Servers auf deinem Rechner, `<name>.<tailnet>.ts.net` = sein Tailscale-Name.
Ausführliche Hintergründe zu jedem Schritt: [NEU-AUFSETZEN.md](NEU-AUFSETZEN.md).

## Ziel

| | |
|---|---|
| Dienst | `home-mcp` (Benutzer `homemcp`), MCP auf `127.0.0.1:8790`, Verwaltungsseite auf `127.0.0.1:8791` |
| Öffentlich | **nur** `https://<name>.<tailnet>.ts.net/mcp` über Tailscale Funnel – Claude verbindet sich aus Anthropics Cloud |
| Verwaltungsseite | nur per SSH-Tunnel: `./verwaltung-oeffnen.sh server` → http://127.0.0.1:8791 |
| Daten | `/srv/home-mcp` (gehört `homemcp`, nie als root ändern) |

## Was ihr vorher braucht

| Was | Wozu |
|---|---|
| Server mit **Debian 12** (arm64 oder x86_64), 2 GB RAM reichen für home-mcp; mit NookBot 4 GB | Raspberry Pi 5 oder kleiner Cloud-Server |
| Benutzer mit `sudo`, SSH-Zugang mit Schlüssel | alle Befehle |
| **Tailscale-Konto mit Admin-Rechten** (euer eigenes Tailnet) | Funnel für Claude, Tailnet für App und NookBot |
| **Google-Konto** mit Zugang zur Google Cloud Console | eigener OAuth-Client für Mail/Kalender/Drive |
| Claude-Konto (claude.ai / App), optional Claude Code | Connector |
| optional: Postgres-Lesezugang, GitLab-Token (`read_api`), Slack-Nutzer-Token (nur lesen), GoatCounter-Token | weitere Werkzeuge |

## 1. Server vorbereiten

```bash
sudo timedatectl set-timezone Europe/Berlin
sudo apt-get update && sudo apt-get install -y curl git python3
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up                       # Link öffnen, Gerät im eigenen Tailnet freigeben
```

Im **Tailscale-Admin** (login.tailscale.com):

- Gerät umbenennen, wie es in der Adresse heißen soll (z. B. `nookserver`). **Später nicht mehr ändern** – die Adresse
  steckt im Claude-Connector und in der App.
- **DNS → MagicDNS an** und **HTTPS Certificates an**.
- **Access controls:** dem Gerät das Funnel-Recht geben, z. B.
  `"nodeAttrs": [{"target": ["autogroup:member"], "attr": ["funnel"]}]`.

Auf deinem Rechner in `~/.ssh/config`:

```
Host server
  HostName <name>.<tailnet>.ts.net
  User <benutzer>
```

Prüfen: `ssh server 'cat /etc/os-release | head -1; uname -m; python3 -V; tailscale status --self --peers=false'`

## 2. home-mcp installieren

Aus dem Repo-Ordner auf deinem Rechner:

```bash
scp home_mcp.py nutzer.py freigaben.py verwaltung.py einrichten.py install.sh home-mcp.service server:/tmp/
ssh server 'sudo bash /tmp/install.sh'
```

`install.sh` legt Benutzer und Ordner an, trägt den Tailscale-Namen als öffentliche Adresse in die Unit ein, startet den
Dienst und schaltet den Funnel ein. Fehlt das Funnel-Recht, zeigt es einen Link – öffnen, freigeben, `install.sh` erneut.

Prüfen: `ssh server 'systemctl is-active home-mcp; curl -fsS http://127.0.0.1:8790/ping'` → `active`, `"ok": true`

## 3. Google-OAuth-Client (eigenes Projekt)

In der [Google Cloud Console](https://console.cloud.google.com/):

1. Neues Projekt (z. B. „home-mcp“).
2. APIs aktivieren: **Gmail, Google Calendar, Google Drive, Google Sheets, Google Docs**.
3. **Google Auth Platform → Branding:** App-Name, Support-Mail. Startseite/Datenschutz nur, wenn Google sie verlangt.
4. **Zielgruppe:** „Extern“, dann **„In Produktion“** veröffentlichen. Im Status „Testen“ verfallen die Anmeldungen nach
   7 Tagen. Ohne Google-Prüfung erscheint bei der Anmeldung „App nicht überprüft“ → Erweitert → Weiter – für eigene Konten ok.
5. **Datenzugriff:** `gmail.readonly`, `gmail.compose`, `calendar.readonly`, `calendar.events`, `drive.readonly`,
   `drive.file`, `spreadsheets`, `documents`.
6. **Clients → Client erstellen → „Desktop-App“**, JSON herunterladen.

```bash
scp ~/Downloads/client_secret_*.json server:/tmp/home-mcp-client.json
ssh server 'sudo bash /tmp/install.sh'          # übernimmt die Datei nach /srv/home-mcp/client.json und löscht die Kopie
```

## 4. Ersten Admin anlegen

Im **eigenen Terminal** (Passwort wird verdeckt abgefragt, mindestens 12 Zeichen; nie über einen Chat):

```bash
ssh -t server 'sudo -u homemcp python3 /opt/home-mcp/einrichten.py passwort <dein-name>'
```

Mit diesem Namen und Passwort meldet man sich an der Verwaltungsseite und beim Claude-Connector an.

## 5. Verwaltungsseite: Google-Konten und Dienste

```bash
./verwaltung-oeffnen.sh server        # SSH-Tunnel + Browser auf http://127.0.0.1:8791
```

Immer `127.0.0.1`, nie `localhost`. Dort anmelden und:

- **Google-Konten** anmelden, Häkchen Mail / Kalender / Drive, danach dem eigenen Nutzer die Rechte geben.
- optional Datenbank (nur Lesezugang), GitLab, Slack (Kanal-Whitelist je Nutzer), Statistik.

## 6. Funnel prüfen

Beim ersten Mal kann es **bis zu ~20 Minuten** dauern, bis die öffentliche Adresse auflöst. Prüfen **von außerhalb des
Tailnets** (z. B. Handy im Mobilfunk):

```bash
curl -fsS https://<name>.<tailnet>.ts.net/ping
curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<name>.<tailnet>.ts.net/mcp     # 401 ist richtig
```

## 7. Claude verbinden

- **Claude App / claude.ai:** Einstellungen → Connectors → benutzerdefinierter Connector → URL
  `https://<name>.<tailnet>.ts.net/mcp`, ohne Client-ID. Anmelden mit Name + Passwort aus Schritt 4.
- **Claude Code** (Rechner im Tailnet):

  ```bash
  claude mcp add --transport http home-mcp https://<name>.<tailnet>.ts.net/mcp \
    --header "Authorization: Bearer $(ssh server sudo cat /srv/home-mcp/token)"
  ```

Test in Claude: „Welche Konten hast du?“

## 8. Bot für NookBot anlegen – Übergabe an Teil 2

Verwaltungsseite → **Neuer Bot** `nookbot` → Rechte anhaken (welche Konten/Kalender/Drive der Bot sehen darf) → zwei
Schlüssel erzeugen. Der Klartext erscheint **nur einmal**, sofort in den Passwort-Manager:

| Schlüssel | gebraucht in |
|---|---|
| **Werkzeuge (Bot)** `hmk_…` | NookBot-Anleitung, Schritt „home-mcp anbinden“ |
| **Freigaben (App)** `hmk_…` | NookBot-App (Einstellungen) und Schritt „Freigaben im Web“ |

Schreibaktionen des Bots (Entwurf, Termin, Drive …) warten immer auf eine Freigabe in der App. Weiter mit
**Teil 2: `docs/neuer-server.md` im Repo nookbot**.

## Sicherung

Alles, was nicht aus dem Repo kommt, liegt in `/srv/home-mcp` – auch alle Schlüssel. Mindestens regelmäßig
verschlüsselt sichern, z. B.:

```bash
sudo tar -C /srv -cpf - home-mcp | gpg -c > home-mcp-$(date +%F).tar.gpg
```

Zurückspielen: `install.sh` laufen lassen (legt `homemcp` an), dann auspacken nach `/srv`,
`sudo chown -R homemcp:homemcp /srv/home-mcp`, Dienst neu starten. Details: [NEU-AUFSETZEN.md](NEU-AUFSETZEN.md#wiederherstellung-aus-der-sicherung).

## Fallstricke

- **401 für alle:** eine Datei in `/srv/home-mcp` gehört root. `sudo find /srv/home-mcp ! -user homemcp -ls` muss leer sein.
- **Gerät umbenannt / heißt `…-1`:** öffentliche Adresse geändert → `install.sh` erneut, Connector neu anlegen, `claude mcp add` neu.
- **Google-Konten fallen nach einer Woche raus:** OAuth-App steht noch auf „Testen“.
- **Funnel nur für home-mcp** und nur auf Port 443. Alles andere (NookBot) bleibt im Tailnet.
