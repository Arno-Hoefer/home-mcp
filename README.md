# home-mcp

MCP-Server für den eigenen Raspberry Pi: Gmail, Google Kalender, Drive/Docs/Sheets, Slack, GitLab und Postgres –
für Claude (Code, App, claude.ai) und für eigene Bots, mit Rechten je Nutzer und Freigaben für alles Schreibende.
Nur Python-Standardbibliothek. Mails werden nie gesendet – es gibt nur Entwürfe.

- Claude Code im Tailnet: `https://<pi>.<tailnet>.ts.net/mcp` mit festem Schlüssel (`sudo cat /srv/home-mcp/token`).
- Claude Cowork / App / claude.ai: dieselbe Adresse als **Custom Connector** (OAuth mit eigenem Passwort).
  Dafür ist genau dieser Dienst per Tailscale Funnel öffentlich; alle anderen Dienste bleiben nur im Tailnet.

Installieren: Dateien nach `/tmp` auf den Pi, `sudo bash /tmp/install.sh`.
Einrichten (interaktiv, auf dem Pi): `sudo -u homemcp python3 /opt/home-mcp/einrichten.py passwort|konto <adresse> [--kalender]`.
Geheimnisse (nie im Git): `/srv/home-mcp/{token,passwort,client.json,oauth.json,konten/*.json}`.

## Datenbank (ab 0.2.0, nur lesen)

Werkzeuge `db_schema` und `db_abfrage` für die Heroku-Postgres (Zugang `nur_lesen`).
- Zugang eintragen (in deinem Terminal, Eingabe verdeckt): `sudo -u homemcp python3 /opt/home-mcp/einrichten.py datenbank`
  → prüft die Verbindung und meldet, ob der Zugang Schreibrechte hätte. Liegt in `/srv/home-mcp/datenbank.json` (600).
- Nur lesen, dreifach: Rolle `nur_lesen`, jede Sitzung `default_transaction_read_only=on`, und nur EINE Anweisung,
  die mit SELECT/WITH/VALUES/TABLE/EXPLAIN beginnt (Kommentare werden vorher entfernt, `$$` abgelehnt).
- Höchstens 500 Zeilen, Zellen über 2000 Zeichen gekürzt, Zeitlimit 60 s (bis 180 s per `timeout_s`), SSL Pflicht.
- Protokoll: jede Abfrage mit Zeilenzahl/Dauer bzw. Fehler im Journal: `journalctl -u home-mcp | grep sql`

## GitLab (ab 0.3.0, nur lesen)

Werkzeuge `gitlab_projekte`, `gitlab_issues`, `gitlab_issue`, `gitlab_mrs`, `gitlab_mr`, `gitlab_datei`, `gitlab_suche`, `gitlab_pipelines` für gitlab.com.
- Token eintragen: `sudo -u homemcp python3 /opt/home-mcp/einrichten.py gitlab` – bricht ab, wenn der Token mehr als `read_api`/`read_user`/`read_repository` darf.
- Nur lesen, zweifach: Token-Bereich `read_api` und im Code ausschließlich GET (`gl()` kennt keine andere Methode).
- Grenzen: Ergebnisse bis 60 000 Zeichen, Diffs je Datei 8 000 / gesamt ~40 000, Job-Logs die letzten 3 000 Zeichen.
- Protokoll: `journalctl -u home-mcp | grep gitlab`

## Mehrere Nutzer + Verwaltungsseite (ab 0.5.0)

- Jeder Nutzer hat Name + Passwort und eigene Rechte: `mail:<adresse>`, `kalender:<adresse>`, `db:<name>`, `gitlab` (`nutzer.py`, `/srv/home-mcp/nutzer.json`).
  Claude sieht nur Werkzeuge, für die der Nutzer ein Recht hat; jeder Aufruf und jedes Konto wird zusätzlich serverseitig geprüft.
- Zugänge (OAuth) gehören fest zu einem Nutzer. Sperren, Löschen, Passwortwechsel und „Überall abmelden“ machen sie sofort ungültig.
- Migration beim ersten Start: altes `passwort` → Nutzer `admin` (Admin, alle Rechte), alte Zugänge gelten als admin, `datenbank.json` → `datenbanken/heroku.json`.
- **Verwaltungsseite** (`verwaltung.py`) im selben Dienst, NUR auf `127.0.0.1:8791` – nicht über Tailscale/Funnel. Vom Mac:
  `ssh -L 8791:127.0.0.1:8791 raspi` und dann http://127.0.0.1:8791 (nicht „localhost“ – Google leitet auf 127.0.0.1 zurück).
  Nutzer anlegen/sperren/löschen, Rechte anhaken, Google-Konten mit geführter Anmeldung, Datenbanken, GitLab, Protokoll.
  Admin-Anmeldung, Sitzungen 8 h, CSRF-Token, Host- und Origin-Prüfung.
- Notausgang im Terminal: `sudo -u homemcp python3 /opt/home-mcp/einrichten.py passwort admin`

## Bots, Freigaben, Slack (ab 0.6.0)

**Bots** (z. B. `nookbot` für NookBot/PicoClaw) legst du auf der Verwaltungsseite unter „Neuer Bot“ an. Bots haben kein
Passwort und sind nie Admin. Sie bekommen Schlüssel (`hmk_<id>_<geheim>`, gespeichert nur als Hash, Klartext nur einmal sichtbar):

- **Werkzeuge (Bot):** als `Authorization: Bearer …` an `/mcp` – der Bot sieht nur, was du ihm per Rechte-Haken gibst.
- **Freigaben (App):** nur für die Freigabe-Schnittstelle. Damit kann man keine Werkzeuge benutzen – und mit dem Bot-Schlüssel nichts freigeben.

**Freigaben:** Bei Bots führen `entwurf_anlegen`, `termin_anlegen` und `termin_gaeste` nichts aus, sondern legen eine
Freigabe an (`freigaben.json`). Ausgeführt wird erst nach deinem Ja – mit genau diesen Argumenten und den Rechten, die der Bot
dann hat. Offene Freigaben verfallen nach 24 Stunden. Entscheiden: in der NookBot-App oder auf der Verwaltungsseite.

Schnittstelle für die App (nur im Tailnet – Anfragen über Funnel werden abgewiesen):

    GET  /app/freigaben[?offen=1]          → {"bot": "...", "freigaben": [{id, tool, text, status, erstellt, …}]}
    POST /app/freigaben/F-xxxxxx  {"entscheidung": "ja"|"nein"}  → die Freigabe mit status/ergebnis

Der Bot fragt den Stand mit dem Werkzeug `freigabe_status` ab.

**Slack (nur lesen):** Token auf der Verwaltungsseite hinterlegen (Nutzer-Token `xoxp-…`, nur Lese-Bereiche; Token mit
Schreib-Bereichen werden abgelehnt). Werkzeuge: `slack_kanaele`, `slack_verlauf`, `slack_thread`, `slack_suche`.
Recht: `slack`. home-mcp ruft ausschließlich lesende API-Methoden auf.

**Feinere Grenzen (0.6.1):** Pro Nutzer und Konto „nur Hauptkalender“ (keine abonnierten/fremden Kalender) und eine
**Slack-Kanal-Whitelist** (Auswahlliste mit Suchfeld). Ohne Whitelist sehen Menschen alle Kanäle, Bots keinen.
`slack_fuer_mich` liefert immer Direktnachrichten an dich, Erwähnungen und eigene Nachrichten – mit Thread bzw. den Nachrichten davor.
