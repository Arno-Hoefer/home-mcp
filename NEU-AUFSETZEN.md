# home-mcp neu aufsetzen

Anleitung, um home-mcp auf einem frischen Raspberry Pi (Debian 12 „bookworm“, arm64) von Null aufzusetzen –
oder einen kaputten Pi aus der Sicherung wiederherzustellen. Reihenfolge einhalten, nach jedem Schritt prüfen.
Was home-mcp kann, steht in der README.md; hier geht es nur um Aufbau und Betrieb.

**Regel Nummer eins:** Alles in `/srv/home-mcp` gehört dem Benutzer `homemcp` und wird nur als dieser geändert
(`sudo -u homemcp …`). Eine Datei, die root gehört, kann der Dienst nicht lesen oder ersetzen – dann bekommen
**alle** Nutzer 401. Prüfen (muss leer bleiben): `sudo find /srv/home-mcp ! -user homemcp -ls`

## So sieht es fertig aus

| Was | Wo |
|---|---|
| Code (gehört root, 644) | `/opt/home-mcp/{home_mcp,nutzer,freigaben,verwaltung,einrichten}.py` |
| Daten + Geheimnisse (gehört `homemcp`, Ordner 700, Dateien 600) | `/srv/home-mcp/` |
| Dienst | `home-mcp.service` – **ein** Prozess: MCP auf `127.0.0.1:8790`, Verwaltungsseite als Thread im selben Prozess auf `127.0.0.1:8791` |
| Öffentlich | Tailscale Funnel: `https://<pi>.<tailnet>.ts.net` (Port 443) → `http://127.0.0.1:8790` |
| Verwaltungsseite | nur per SSH-Tunnel vom Mac: `./verwaltung-oeffnen.sh` → http://127.0.0.1:8791 |
| Systemnutzer | `homemcp` (System-Nutzer, ohne Home, Shell `nologin`) |
| Pakete | `python3` (≥ 3.10, Debian 12 hat 3.11), `postgresql-client` (`psql`, für die Datenbank-Werkzeuge), `curl`, `tailscale` |

Eine eigene systemd-Unit für die Verwaltungsseite gibt es **nicht** – sie startet und stoppt mit `home-mcp`.

Dateien in `/srv/home-mcp` (alle entstehen von selbst bzw. über `einrichten.py` / Verwaltungsseite – nie von Hand anlegen):

| Datei | Inhalt | entsteht durch |
|---|---|---|
| `token` | fester Schlüssel für Claude Code im Tailnet | `install.sh` (nur wenn noch keiner da ist) |
| `client.json` | Google-OAuth-Client (Typ Desktop-App) | du, siehe Schritt 4 |
| `nutzer.json` | Nutzer, Passwort-Hashes, Rechte, Bots, Schlüssel-Hashes | `einrichten.py passwort` / Verwaltungsseite |
| `oauth.json` | Claude-Connector-Zugänge (nur Hashes) | Anmeldung in Claude |
| `konten/<adresse>.json` | Google-Refresh-Token je Konto | Google-Anmeldung |
| `datenbanken/<name>.json` | Postgres-Zugang (nur lesen) | `einrichten.py datenbank` / Verwaltungsseite |
| `gitlab.json`, `slack.json`, `goatcounter.json` | Token der jeweiligen Dienste | Verwaltungsseite (GitLab auch `einrichten.py gitlab`) |
| `freigaben.json` | offene und erledigte Freigaben der Bots | Bots |
| `ablage/` | Upload-Bytes von Bots bis zur Freigabe (höchstens 300 MB) | wird bei Bedarf angelegt, darf fehlen |
| `passwort.alt` | Überbleibsel der Umstellung auf mehrere Nutzer (0.5.0) | nur auf alten Installationen, kann bleiben |

## 1. Voraussetzungen

- Raspberry Pi mit Debian 12 / Raspberry Pi OS Lite (64 Bit), Benutzer `admin` mit `sudo` ohne Passwort, SSH vom Mac.
  Auf dem Mac in `~/.ssh/config` ein Eintrag `Host raspi` (Hostname = Tailscale-Name oder IP, `User admin`).
- Tailscale-Konto (Tailnet), auf dem Pi installiert und angemeldet:

      curl -fsSL https://tailscale.com/install.sh | sh
      sudo tailscale up            # Link im Browser öffnen, Gerät freigeben

  Gerätename im Tailscale-Admin so setzen, wie er in der öffentlichen Adresse stehen soll (hier: `raspi`). **Gibt es den alten Pi dort noch, zuerst löschen** – sonst heißt
  der neue `raspi-1` und die öffentliche Adresse ändert sich (siehe Fallstricke).
- Im Tailscale-Admin: **DNS → MagicDNS an** und **HTTPS-Zertifikate an**; unter **Access controls** muss der Pi das
  Funnel-Recht haben (`nodeAttrs` mit `"attr": ["funnel"]`). Fehlt es, zeigt `tailscale funnel` einen Link, über den man es freischaltet.
- Google-Konto mit Zugriff auf die Google Cloud Console (für den OAuth-Client, Schritt 4).
- Ein Claude-Konto (claude.ai / App / Cowork) und optional Claude Code auf dem Mac.
- Die Geheimnisse selbst (Passwörter, Google-Anmeldungen, Token) trägt der Besitzer **selbst** ein – im eigenen Terminal
  (`einrichten.py`) oder auf der Verwaltungsseite, nie über einen Chat.

## 2. Pi prüfen

    ssh raspi 'cat /etc/os-release | head -2; uname -m; python3 --version; tailscale status --self --peers=false'

Erwartet: bookworm, `aarch64`, Python 3.11, der Pi als `raspi` im Tailnet.

## 3. Installieren

Vom Mac aus dem Repo-Ordner:

    scp home_mcp.py nutzer.py freigaben.py verwaltung.py einrichten.py install.sh home-mcp.service raspi:/tmp/
    ssh raspi 'sudo bash /tmp/install.sh'

`install.sh` macht: `postgresql-client` (und `curl`) installieren, falls sie fehlen · Nutzer `homemcp` anlegen ·
`/srv/home-mcp` und `/srv/home-mcp/konten` (700, `homemcp`) · Code nach `/opt/home-mcp` · Unit nach `/etc/systemd/system` ·
`token` erzeugen, falls keiner da ist · Dienst aktivieren und starten · `/ping` prüfen · Funnel einschalten (Schritt 7).
Das Skript darf beliebig oft laufen; vorhandene Daten in `/srv/home-mcp` bleiben unberührt.

Hat der Pi einen anderen Tailscale-Namen, vorher in `home-mcp.service` die Zeile
`Environment=HOME_MCP_PUBLIC=https://<pi>.<tailnet>.ts.net` anpassen – das ist die Adresse, die home-mcp Claude als
OAuth-Aussteller nennt. Sie muss genau der Funnel-Adresse entsprechen.

Prüfen:

    ssh raspi 'systemctl is-active home-mcp; curl -fsS http://127.0.0.1:8790/ping; echo; sudo ss -ltnp | grep -E ":879[01]"'

Erwartet: `active`, `{"ok": true, "dienst": "home-mcp", "version": "…"}`, und **ein** `python3`-Prozess auf 8790 und 8791.

**Aus einer Sicherung wiederherstellen?** Jetzt direkt mit [Wiederherstellung](#wiederherstellung-aus-der-sicherung)
weitermachen und die Schritte 4–6 und 9 auslassen – Nutzer, Konten, Bots und Claude-Zugänge stecken in der Sicherung.

## 4. Google-OAuth-Client (einmalig je Google-Cloud-Projekt)

In der [Google Cloud Console](https://console.cloud.google.com/) – ein vorhandenes Projekt weiterbenutzen, dann reicht es,
die alte `client.json` aus der Sicherung zu nehmen (Datei liegt im Backup unter `home-mcp/client.json`).

Neu einrichten:

1. Projekt anlegen (z. B. „home-mcp“).
2. **APIs aktivieren:** Gmail API, Google Calendar API, Google Drive API, Google Sheets API, Google Docs API.
3. **Google Auth Platform → Branding** (Zustimmungsbildschirm): App-Name „home-mcp“, Support-Mail, Startseite und
   Datenschutzerklärung (eine eigene Website mit einer Seite zu home-mcp und einer Datenschutzseite), autorisierte Domain dieser Website.
4. **Zielgruppe:** „Extern“. Veröffentlichungsstatus **„In Produktion“** – im Status „Testen“ verfallen die Refresh-Tokens
   nach 7 Tagen und alle Google-Konten müssen neu angemeldet werden. Eine Prüfung durch Google ist für die eigenen Konten
   nicht nötig; bei der Anmeldung erscheint dann „Google hat diese App nicht überprüft“ → Erweitert → Weiter.
5. **Datenzugriff (Bereiche):** `gmail.readonly`, `gmail.compose`, `calendar.readonly`, `calendar.events`,
   `drive.readonly`, `drive.file`, `spreadsheets`, `documents` (alle unter `https://www.googleapis.com/auth/`).
6. **Clients → Client erstellen → Typ „Desktop-App“**, JSON herunterladen. Weiterleitungs-URIs muss man bei Desktop-Apps
   nicht eintragen – Google erlaubt jede `http://127.0.0.1:<port>/`; home-mcp nutzt 8791 (Verwaltungsseite) und 8765 (`einrichten.py`).

Auf den Pi bringen (die Datei nicht ins Repo legen):

    scp ~/Downloads/client_secret_*.json raspi:/tmp/home-mcp-client.json
    ssh raspi 'sudo bash /tmp/install.sh'      # übernimmt /tmp/home-mcp-client.json als client.json (600, homemcp) und löscht die Kopie

Prüfen: `ssh raspi 'sudo ls -l /srv/home-mcp/client.json'` → `-rw------- homemcp homemcp`.

## 5. Ersten Admin anlegen

Im **eigenen** Terminal (Passwort wird verdeckt abgefragt, mindestens 12 Zeichen):

    ssh -t raspi 'sudo -u homemcp python3 /opt/home-mcp/einrichten.py passwort admin'

Der erste Nutzer wird Admin und Besitzer des festen Schlüssels (`token`). Mit diesem Namen und Passwort meldet man sich
an der Verwaltungsseite und beim Claude-Connector an. Derselbe Befehl ist der Notausgang, wenn man sich ausgesperrt hat.

## 6. Verwaltungsseite: Konten und Dienste verbinden

Vom Mac:

    ./verwaltung-oeffnen.sh            # oder: ./verwaltung-oeffnen.sh <ssh-host>, bzw. HOME_MCP_SSH=<ssh-host>

Das Skript baut den Tunnel `ssh -f -N -L 8791:127.0.0.1:8791 raspi` im Hintergrund auf (nur wenn Port 8791 nicht schon
lauscht), öffnet http://127.0.0.1:8791 in Chrome (sonst im Standardbrowser) und zeigt, wie man den Tunnel wieder schließt:

    pkill -f "ssh -f -N -o ExitOnForwardFailure=yes .*-L 8791:127.0.0.1:8791"

Immer `127.0.0.1`, nie `localhost` – Google leitet nach der Anmeldung genau dorthin zurück.

Auf der Seite (als Admin angemeldet):

- **Google-Konten:** je Konto anmelden, Häkchen für Mail / Kalender / Drive setzen. Danach dem Nutzer die Rechte geben.
- **Datenbanken:** Postgres-URL eines **reinen Lesezugangs** (`postgres://benutzer:passwort@host:5432/db`); die Seite prüft,
  ob der Zugang Schreibrechte hätte.
- **GitLab:** Personal Access Token **nur** mit `read_api` (andere Bereiche werden abgelehnt).
- **Slack:** Nutzer-Token `xoxp-…` mit nur lesenden Bereichen; Kanal-Whitelist je Nutzer.
- **Statistik:** GoatCounter-Seite und API-Token (nur lesen).
- Weitere **Nutzer** anlegen, Rechte anhaken, „nur Hauptkalender“ je Konto.

Dasselbe ohne Verwaltungsseite (z. B. wenn der Tunnel nicht geht), jeweils mit `ssh -t raspi 'sudo -u homemcp python3 /opt/home-mcp/einrichten.py …'`:
`konto <adresse> [--kalender] [--drive]`, `datenbank [name]`, `gitlab`, optional `--fuer NAME`.
Slack und Statistik gibt es nur auf der Verwaltungsseite.

## 7. Tailscale Funnel

`install.sh` versucht es selbst; von Hand:

    ssh raspi 'sudo tailscale funnel --bg --https=443 http://127.0.0.1:8790'
    ssh raspi 'sudo tailscale funnel status'

Erwartet:

    # Funnel on:
    #     - https://<pi>.<tailnet>.ts.net
    https://<pi>.<tailnet>.ts.net (Funnel on)
    |-- / proxy http://127.0.0.1:8790

Nur **dieser** Dienst gehört auf Port 443 und in den Funnel – Claudes Connector-Dienst erreicht nur den Standardport.
Andere Dienste auf dem Pi laufen mit `tailscale serve --bg --https=<port> …` auf anderen Ports und nur im Tailnet
(ihre Einträge stehen in der Sicherung unter `system/tailscale-serve.txt`, gehören aber nicht zu home-mcp).
Abschalten: `sudo tailscale funnel --https=443 off`.

**Geduld:** Nach dem ersten Einschalten (oder auf einem neuen Gerät) dauert es oft **bis zu ~20 Minuten**, bis der
öffentliche DNS-Name auflöst und das Zertifikat da ist. Bis dahin scheitert der Aufruf von außen – nichts umbauen, warten.

Prüfen – **von außerhalb des Tailnets** (z. B. Handy im Mobilfunk, oder Mac mit Tailscale aus):

    curl -fsS https://<pi>.<tailnet>.ts.net/ping
    curl -fsS https://<pi>.<tailnet>.ts.net/.well-known/oauth-authorization-server     # issuer = genau diese Adresse
    curl -s -o /dev/null -w '%{http_code}\n' -X POST https://<pi>.<tailnet>.ts.net/mcp  # 401 ohne Schlüssel ist richtig

## 8. Claude verbinden

**Claude App / claude.ai / Cowork (Custom Connector):** Einstellungen → Connectors → benutzerdefinierten Connector hinzufügen,
URL `https://<pi>.<tailnet>.ts.net/mcp`, keine Client-ID/kein Secret (Claude registriert sich selbst, OAuth 2.1 mit PKCE).
Beim Verbinden öffnet sich die Anmeldeseite von home-mcp → Name + Passwort aus Schritt 5. Claude sieht danach nur die
Werkzeuge, für die dieser Nutzer Rechte hat. Abmelden: Verwaltungsseite → „Überall abmelden“ oder Passwort ändern.

**Claude Code** (Mac im Tailnet, fester Schlüssel):

    claude mcp add --transport http home-mcp https://<pi>.<tailnet>.ts.net/mcp \
      --header "Authorization: Bearer $(ssh raspi sudo cat /srv/home-mcp/token)"

Den Schlüssel nicht in Dateien im Repo oder in Chats kopieren.

## 9. Bots anlegen (z. B. für NookBot)

Verwaltungsseite → **Neuer Bot** (Name z. B. `nookbot`). Dann zwei Schlüssel erzeugen – der Klartext erscheint **nur einmal**:

- **Werkzeuge (Bot)** → in die Bot-Konfiguration als MCP-Server mit `Authorization: Bearer hmk_<id>_<geheim>`.
  Läuft der Bot auf demselben Pi, nimmt er `http://127.0.0.1:8790/mcp` (ohne Umweg über den Funnel), sonst die Funnel-Adresse.
- **Freigaben (App)** → in die App, die Freigaben entscheidet. Sie spricht `/app/freigaben` über die **Tailnet**-Adresse an;
  Anfragen über den Funnel werden dort abgewiesen.

Danach dem Bot Rechte anhaken (und bei Slack eine Kanal-Whitelist – ohne sieht ein Bot keinen Kanal).
Schreibaktionen eines Bots warten immer auf eine Freigabe. Verlorener Schlüssel: auf der Seite löschen, neuen erzeugen.

## 10. Prüfen – alles auf einen Blick

    ssh raspi '
      systemctl is-active home-mcp; systemctl is-enabled home-mcp
      curl -fsS http://127.0.0.1:8790/ping; echo
      curl -s -o /dev/null -w "verwaltung %{http_code}\n" http://127.0.0.1:8791/
      T=$(sudo cat /srv/home-mcp/token); curl -s http://127.0.0.1:8790/mcp -H "Authorization: Bearer $T" \
        -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}" \
        | python3 -c "import json,sys; print(len(json.load(sys.stdin)[\"result\"][\"tools\"]), \"Werkzeuge\")"
      sudo tailscale funnel status
      sudo find /srv/home-mcp ! -user homemcp -ls          # muss leer sein
      sudo ls -la /srv/home-mcp
      journalctl -u home-mcp -n 30 --no-pager'

Erwartet: `active`/`enabled`, `ok: true`, `verwaltung 200`, eine Zahl > 0 Werkzeuge (je nach Rechten des Token-Nutzers),
Funnel on für Port 443, keine Ausgabe vom `find`. Danach in Claude z. B. „Welche Konten hast du?“ (Werkzeug `konten`).

Tests auf dem Mac (gemockte Google-API, legen nichts an): `python3 -m unittest discover -s tests`

## Wiederherstellung aus der Sicherung

Die nächtliche Sicherung des Pi (`pi-backup.sh`, liegt im Home-Dashboard-Repo unter `deploy/backup/`) packt in
`pi-backup-<datum>.tar.gz` u. a.:

- `home-mcp.tar` – der komplette Ordner `/srv/home-mcp` mit Besitzer und Rechten,
- `system/home-mcp.service` – die Unit, wie sie lief,
- `system/tailscale-serve.txt` – Ausgabe von `tailscale serve status` (alle Serve-/Funnel-Einträge des Pi).

Der Code selbst ist **nicht** in der Sicherung – der kommt aus diesem Repo.

1. Schritte 1–3 (Tailscale, `install.sh`). `install.sh` legt den Nutzer `homemcp` an – das muss **vor** dem Auspacken passieren.
2. Archiv auf den Pi holen (mit eingerichtetem rclone-Ziel `pibackup:`, siehe `pi-backup-einrichten.sh`; ohne das braucht
   man das Passwort der rclone-Verschlüsselung):

       rclone lsf pibackup:taeglich | sort | tail -3
       mkdir -p ~/restore && rclone copy pibackup:taeglich/pi-backup-<datum>.tar.gz ~/restore/
       mkdir -p ~/restore/x && tar -xzf ~/restore/pi-backup-<datum>.tar.gz -C ~/restore/x

3. Einspielen (als root auspacken, damit Rechte erhalten bleiben; danach Besitzer erzwingen, weil die UID auf dem neuen Pi anders sein kann):

       sudo systemctl stop home-mcp
       sudo tar -C /srv -xpf ~/restore/x/home-mcp.tar
       sudo chown -R homemcp:homemcp /srv/home-mcp
       sudo chmod 700 /srv/home-mcp
       sudo find /srv/home-mcp ! -user homemcp -ls          # muss leer sein
       diff ~/restore/x/system/home-mcp.service /etc/systemd/system/home-mcp.service   # Unterschiede verstehen, nicht blind kopieren
       sudo systemctl start home-mcp

   Der `token` aus der Sicherung überschreibt den neu erzeugten – Claude Code muss also nicht neu eingerichtet werden.
4. Funnel (Schritt 7) und auf die DNS-Freischaltung warten.
5. Prüfen (Schritt 10). Weil `oauth.json`, `nutzer.json` und alle Konten zurück sind, funktionieren Claude-Connector,
   Bots und Google-Konten ohne neue Anmeldung – **sofern die öffentliche Adresse gleich geblieben ist**.
6. Aufräumen: `rm -rf ~/restore` (das Archiv enthält alle Geheimnisse im Klartext).

Probelauf ohne Eingriff ins System: `pi-backup-pruefen.sh` (holt die neueste Sicherung und prüft sie in einem Testordner).

## Aktualisieren (neue Version)

Wie Schritt 3: Dateien nach `/tmp`, `sudo bash /tmp/install.sh`. Daten bleiben, der Dienst wird neu gestartet.
Version prüfen: `curl -fsS http://127.0.0.1:8790/ping`.

## Fallstricke

- **401 für alle** nach Handarbeit in `/srv/home-mcp`: eine Datei gehört root. `sudo find /srv/home-mcp ! -user homemcp -ls`,
  dann `sudo chown -R homemcp:homemcp /srv/home-mcp`. Künftig nur `sudo -u homemcp …`.
- **Funnel-Adresse geht von außen nicht**, im Tailnet aber schon: DNS/Zertifikat brauchen beim ersten Mal bis ~20 Minuten.
  Sonst: HTTPS-Zertifikate und Funnel-Recht im Tailscale-Admin prüfen.
- **Neuer Pi heißt `raspi-1`:** der alte Knoten steht noch im Tailnet. Alten Knoten löschen, neuen umbenennen –
  sonst stimmen `HOME_MCP_PUBLIC`, Connector-URL und Claude-Code-Eintrag nicht mehr. Ändert sich die Adresse wirklich,
  müssen `HOME_MCP_PUBLIC` in der Unit, der Claude-Connector (neu hinzufügen) und `claude mcp add` angepasst werden.
- **Verwaltungsseite über `localhost` geöffnet:** Google-Anmeldung landet im Nichts. Immer http://127.0.0.1:8791.
- **Port 8791 auf dem Mac belegt** (alter Tunnel): `lsof -nP -iTCP:8791 -sTCP:LISTEN`, den Prozess beenden.
- **Google-Konten fallen nach einer Woche raus:** OAuth-Zustimmungsbildschirm steht auf „Testen“ statt „In Produktion“.
- **„Kein Refresh-Token erhalten“:** Konto einmal unter https://myaccount.google.com/permissions von der App trennen und neu anmelden.
- **Funnel-Befehl hängt in `install.sh`:** das Funnel-Recht fehlt; den Link aus der Meldung öffnen, dann `install.sh` erneut.
- **Der Pi hat kein funktionierendes IPv6** – home-mcp bevorzugt deshalb IPv4; nichts einstellen.
- **Speicher:** die Unit begrenzt auf 200 MB; Anfragen an `/mcp` dürfen bis 40 MB groß sein (Uploads als Base64).
- **Geheimnisse** (`token`, `client.json`, `nutzer.json`, `oauth.json`, `konten/`, `datenbanken/`, `*.json` der Dienste)
  gehören nie ins Git – die `.gitignore` schließt `*.json` aus. Nicht per Chat weitergeben, nicht ausgeben lassen.
