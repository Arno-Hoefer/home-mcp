"""
Verwaltungsseite von home-mcp – Nutzer, Bots + Schlüssel, Freigaben, Rechte, Google-Konten, Datenbanken, GitLab, Slack, Protokoll.

Lauscht NUR auf 127.0.0.1:8791 (kein Tailscale, kein Funnel), als Thread im home-mcp-Dienst. Vom Mac aus per SSH-Tunnel:
    ./verwaltung-oeffnen.sh [ssh-host]     (baut den Tunnel im Hintergrund auf und öffnet den Browser; Standard raspi)
    ssh -L 8791:127.0.0.1:8791 raspi      → im Browser http://127.0.0.1:8791   (dasselbe von Hand)
Anmeldung mit Name + Passwort eines Admins. Jede Änderung hat ein CSRF-Token, Host/Origin werden geprüft.
Google-Anmeldung läuft über die Desktop-App-Weiterleitung auf http://127.0.0.1:8791/ – darum die Seite immer über 127.0.0.1 öffnen.
"""
import base64
import datetime
import hashlib
import html
import json
import os
import re
import secrets
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import freigaben
import nutzer

PORT = int(os.environ.get("HOME_MCP_ADMIN_PORT", "8791"))
ORIGIN = f"http://127.0.0.1:{PORT}"
REDIRECT = ORIGIN + "/"
SESSION_TTL = 8 * 3600
MAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose"]
CAL_SCOPES = ["https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/calendar.events"]
DRIVE_SCOPES = ["https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/drive.file",
                "https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/documents"]
GL_OK_SCOPES = {"read_api", "read_user", "read_repository"}
SLACK_BAD = re.compile(r"(:write|^admin|:manage|^chat:|^files:write|^reactions:write|^pins:write|^reminders:write)")
_sessions: dict[str, dict] = {}
_lock = threading.Lock()
mcp = None  # das home_mcp-Modul (für Protokoll, Zugänge, psql)

CSS = """
:root{--bg:#f6f4ef;--fg:#22201c;--mut:#6b655a;--card:#fff;--line:#e3ded3;--acc:#2f6b4e;--warn:#9b2c1f}
@media (prefers-color-scheme:dark){:root{--bg:#1b1a17;--fg:#ece8df;--mut:#a39d90;--card:#26241f;--line:#3a372f;--acc:#6bb38c;--warn:#e07a6a}}
body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--fg);max-width:900px;margin:0 auto;padding:16px}
h1{font-size:22px}h2{font-size:18px;margin:0 0 10px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin:14px 0}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top;font-size:14px}
input,select,button{font-size:15px;padding:7px 9px;border-radius:7px;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
button{background:var(--acc);color:#fff;border:0;cursor:pointer}button.l{background:transparent;color:var(--acc);border:1px solid var(--line)}
button.x{background:transparent;color:var(--warn);border:1px solid var(--line)}
form.i{display:inline}.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:6px 0}
.mut{color:var(--mut);font-size:13px}.msg{padding:10px;border-radius:8px;background:var(--card);border:1px solid var(--acc)}
.err{border-color:var(--warn);color:var(--warn)}label.r{display:block;margin:3px 0;font-size:14px}
pre{white-space:pre-wrap;font-size:12px;max-height:420px;overflow:auto}nav a{margin-right:12px;color:var(--acc)}
"""


def page(title: str, body: str) -> str:
    return (f'<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<title>{html.escape(title)}</title><style>{CSS}</style><body>{body}</body></html>')


def e(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


# ── Hilfen ─────────────────────────────────────────────────────────

def client_conf() -> dict:
    with open(nutzer.path("client.json"), encoding="utf-8") as f:
        c = json.load(f)
    return c.get("installed") or c.get("web") or c


def pg_check(url: str) -> str:
    """Verbindung testen; Text mit Nutzer, Server und ob der Zugang schreiben dürfte."""
    env = mcp.pg_env(url, 20)
    sql = ("SELECT current_user || ' auf ' || current_database() || ' · Server ' || current_setting('server_version') || "
           "' · Schreibrechte: ' || coalesce((SELECT string_agg(DISTINCT privilege_type, ', ') FROM information_schema.role_table_grants "
           "WHERE grantee = current_user AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')), 'keine')")
    r = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-c", sql], env=env, capture_output=True, text=True, timeout=30)
    if r.returncode:
        raise ValueError("Verbindung klappt nicht: " + r.stderr.strip().replace(env["PGPASSWORD"] or "\0", "***")[:400])
    return r.stdout.strip()


def gl_check(tok: str) -> dict:
    def get(p):
        req = urllib.request.Request("https://gitlab.com/api/v4" + p, headers={"PRIVATE-TOKEN": tok})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    try:
        me, info = get("/user"), get("/personal_access_tokens/self")
    except urllib.error.HTTPError as ex:
        raise ValueError(f"GitLab lehnt den Token ab ({ex.code}).") from None
    extra = set(info.get("scopes", [])) - GL_OK_SCOPES
    if extra:
        raise ValueError(f"Token hat Schreibrechte ({', '.join(sorted(extra))}) – bitte einen NUR mit read_api anlegen.")
    return {"user": me.get("username"), "scopes": info.get("scopes", []), "expires": info.get("expires_at")}


def slack_check(tok: str) -> dict:
    """Token prüfen: gültig und ohne Schreib-Bereiche."""
    if not re.match(r"^xox[pb]-", tok):
        raise ValueError("Slack-Token beginnt mit xoxp- (Nutzer, kann auch suchen) oder xoxb- (Bot).")
    try:
        d = mcp.slack("auth.test", tok=tok)
    except mcp.ToolError as ex:
        raise ValueError(str(ex)) from None
    scopes = [x.strip() for x in d.get("_scopes", "").split(",") if x.strip()]
    bad = [x for x in scopes if SLACK_BAD.search(x)]
    if bad:
        raise ValueError(f"Token hat Schreibrechte ({', '.join(bad)}) – bitte einen nur mit Lese-Bereichen anlegen "
                         "(channels:history, channels:read, groups:history, groups:read, im:history, im:read, mpim:history, mpim:read, users:read, search:read).")
    return {"user": d.get("user"), "team": d.get("team"), "scopes": scopes}


def gc_check(url: str, tok: str) -> int:
    """Liest die Besuche der letzten 7 Tage – klappt das, darf der Token Statistik lesen."""
    url = url.strip().rstrip("/")
    if not re.match(r"^https://[a-z0-9-]+(\.[a-z0-9-]+)+$", url):
        raise ValueError("Adresse wie https://name.goatcounter.com eingeben (ohne /count).")
    end = datetime.date.today() + datetime.timedelta(days=1)
    q = urllib.parse.urlencode({"start": (end - datetime.timedelta(days=7)).isoformat(), "end": end.isoformat()})
    req = urllib.request.Request(f"{url}/api/v0/stats/total?{q}", headers={"Authorization": "Bearer " + tok, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return int(json.loads(r.read()).get("total", 0))
    except urllib.error.HTTPError as ex:
        raise ValueError(f"GoatCounter lehnt den Token ab ({ex.code}).") from None
    except (urllib.error.URLError, ValueError) as ex:
        raise ValueError(f"GoatCounter nicht erreichbar: {ex}") from None


def gc_load() -> list:
    try:
        return json.load(open(nutzer.path("goatcounter.json"), encoding="utf-8")).get("seiten", [])
    except (OSError, ValueError):
        return []


def write_secret(p: str, d: dict) -> None:
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    nutzer._write_json(p, d)


# ── Seite ──────────────────────────────────────────────────────────

def render(s: dict) -> str:
    me = s["user"]
    d = nutzer.load()
    rights = nutzer.all_rights()
    names = sorted(d["nutzer"])
    csrf = s["csrf"]
    hid = f'<input type="hidden" name="csrf" value="{e(csrf)}">'

    def form(was, inner, cls="i", confirm=None):
        oc = f' onsubmit="return confirm({e(json.dumps(confirm))})"' if confirm else ""
        return f'<form method="post" action="/aktion" class="{cls}"{oc}>{hid}<input type="hidden" name="was" value="{e(was)}">{inner}</form>'

    msg = s.pop("msg", None)
    out = [f'<h1>home-mcp · Verwaltung</h1><div class="row"><span class="mut">Angemeldet als <b>{e(me)}</b> · nur über 127.0.0.1 erreichbar</span>'
           + form("abmelden", '<button class="l">Abmelden</button>') + '</div>'
           '<nav><a href="#nutzer">Nutzer</a><a href="#freigaben">Freigaben</a><a href="#google">Google</a><a href="#db">Datenbanken</a><a href="#gitlab">GitLab</a><a href="#slack">Slack</a><a href="#statistik">Statistik</a><a href="#log">Protokoll</a></nav>']
    if msg:
        out.append(f'<p class="msg{" err" if msg[0] == "!" else ""}">{e(msg.lstrip("!"))}</p>')

    # Nutzer
    rows = []
    for n in names:
        u = d["nutzer"][n]
        boxes = "".join(f'<label class="r"><input type="checkbox" name="recht" value="{e(r)}"{" checked" if r in u.get("rechte", []) else ""}> {e(lbl)}</label>'
                        + (f'<label class="r" style="margin-left:26px"><input type="checkbox" name="nurhaupt" value="{e(r[9:])}"'
                           f'{" checked" if r[9:] in u.get("kalender_nur_haupt", []) else ""}> nur Hauptkalender (keine abonnierten/fremden)</label>'
                           if r.startswith("kalender:") else "")
                        for r, lbl in rights) or '<span class="mut">Noch keine Ressourcen eingerichtet.</span>'
        bot = u.get("bot")
        state = ("🔒 gesperrt" if u.get("gesperrt") else "aktiv") + (" · Admin" if u.get("admin") else "") + (" · 🤖 Bot (Schreiben nur mit Freigabe)" if bot else "")
        tok = " · fester Schlüssel (Claude Code)" if nutzer.token_owner() == n else ""
        acts = [form("rechte", f'<input type="hidden" name="name" value="{e(n)}">{boxes}<div class="row"><button>Rechte speichern</button></div>', cls="")]
        if bot:
            keys = "".join(f'<tr><td><code>hmk_{e(k["id"])}_…</code></td><td>{"🔧 Werkzeuge (Bot)" if k["art"] == "mcp" else "✅ Freigaben (App)"}</td>'
                           f'<td>{e(k["name"])}</td><td class="mut">{time.strftime("%d.%m.%y", time.localtime(k["erstellt"]))} · zuletzt '
                           f'{time.strftime("%d.%m. %H:%M", time.localtime(k["zuletzt"])) if k.get("zuletzt") else "nie"}</td><td>'
                           + form("key_weg", f'<input type="hidden" name="name" value="{e(n)}"><input type="hidden" name="kid" value="{e(k["id"])}">'
                                  '<button class="x">Widerrufen</button>', confirm="Schlüssel widerrufen? Was ihn nutzt, verliert sofort den Zugang.") + '</td></tr>'
                           for k in u.get("schluessel", []))
            acts.append(f'<table>{keys or "<tr><td class=mut>Noch kein Schlüssel.</td></tr>"}</table>'
                        + form("key_neu", f'<div class="row"><input type="hidden" name="name" value="{e(n)}"><select name="art">'
                               '<option value="mcp">für den Bot (Werkzeuge)</option><option value="freigabe">für die App (Freigaben)</option></select>'
                               '<input name="label" placeholder="wofür (z. B. PicoClaw)" maxlength="40"><button class="l">Schlüssel erzeugen</button></div>', cls=""))
        else:
            acts.append('<div class="row">' + form("passwort", f'<input type="hidden" name="name" value="{e(n)}"><input type="password" name="pw" placeholder="neues Passwort" minlength="12" required> <button class="l">Passwort ändern</button>'))
        if bot:
            acts.append('<div class="row">')
        if n != me:
            acts.append(form("sperren" if not u.get("gesperrt") else "entsperren", f'<input type="hidden" name="name" value="{e(n)}"><button class="l">{"Sperren" if not u.get("gesperrt") else "Entsperren"}</button>'))
            if not bot:
                acts.append(form("admin", f'<input type="hidden" name="name" value="{e(n)}"><button class="l">{"Admin entziehen" if u.get("admin") else "Zum Admin machen"}</button>'))
            acts.append(form("loeschen", f'<input type="hidden" name="name" value="{e(n)}"><button class="x">Löschen</button>', confirm=f"{n} wirklich löschen?"))
        if not bot:
            acts.append(form("abmelden_alle", f'<input type="hidden" name="name" value="{e(n)}"><button class="l">Überall abmelden</button>'))
        acts.append('</div>')
        info = "" if bot else f"<br>{mcp.sessions_of(n)} Claude-Verbindung(en)"
        rows.append(f'<tr><td><b>{e(n)}</b><div class="mut">{e(state)}{e(tok)}{info}</div></td><td>{"".join(acts)}</td></tr>')
    out.append('<section id="nutzer"><h2>Nutzer</h2><table>' + "".join(rows) + '</table>'
               '<h2 style="margin-top:16px">Neuer Nutzer</h2>' + form("neu", '<div class="row"><input name="name" placeholder="name (z. B. jana)" pattern="[a-z][a-z0-9_-]{1,23}" required>'
               '<input type="password" name="pw" placeholder="Passwort (min. 12)" minlength="12" required><label><input type="checkbox" name="admin"> Admin</label>'
               '<button>Anlegen</button></div>', cls="") +
               '<p class="mut">Danach Rechte anhaken. Die Person verbindet in IHREM Claude-Konto den Connector <code>https://<pi>.<tailnet>.ts.net/mcp</code> '
               'und meldet sich mit diesem Namen und Passwort an. Sperren, Löschen und Passwortwechsel melden sie sofort überall ab.</p>'
               '<h2 style="margin-top:16px">Neuer Bot</h2>' + form("bot_neu", '<div class="row"><input name="name" placeholder="name (z. B. nookbot)" pattern="[a-z][a-z0-9_-]{1,23}" required>'
               '<button>Bot anlegen</button></div>', cls="") +
               '<p class="mut">Bots haben kein Passwort, sondern Schlüssel: einen für den Bot selbst (Werkzeuge benutzen) und einen für die App (Freigaben entscheiden). '
               'Schreibaktionen eines Bots – Entwürfe, Termine, Einladungen – werden erst ausgeführt, wenn du sie freigibst. '
               'Danach Rechte anhaken, am besten erst nur lesende.</p></section>')

    # Freigaben
    fr = []
    for f in freigaben.liste(n=40):
        st = {"offen": "⏳ wartet", "laeuft": "läuft", "ausgefuehrt": "✓ ausgeführt", "abgelehnt": "✗ abgelehnt", "fehler": "⚠ Fehler", "abgelaufen": "abgelaufen"}.get(f["status"], f["status"])
        btn = ""
        if f["status"] == "offen":
            btn = (form("freigabe_ja", f'<input type="hidden" name="fid" value="{e(f["id"])}"><button>Ausführen</button>', confirm="Wirklich ausführen?") + " "
                   + form("freigabe_nein", f'<input type="hidden" name="fid" value="{e(f["id"])}"><button class="x">Ablehnen</button>'))
        fr.append(f'<tr><td><b>{e(f["id"])}</b><div class="mut">{e(f["user"])} · {time.strftime("%d.%m. %H:%M", time.localtime(f["erstellt"]))}</div></td>'
                  f'<td><pre style="max-height:160px;margin:0">{e(f["text"])}</pre>{("<div class=mut>" + e(f["ergebnis"]) + "</div>") if f.get("ergebnis") else ""}</td>'
                  f'<td>{e(st)}<div class="row">{btn}</div></td></tr>')
    out.append('<section id="freigaben"><h2>Freigaben</h2><table>' + ("".join(fr) or '<tr><td class="mut">Keine.</td></tr>') + '</table>'
               '<p class="mut">Normalerweise entscheidest du in der NookBot-App. Offene Freigaben verfallen nach 24 Stunden.</p></section>')

    # Google
    opts = "".join(f'<option value="{e(n)}"{" selected" if n == me else ""}>{e(n)}</option>' for n in names)
    g = []
    for a in nutzer.accounts():
        try:
            kann = json.load(open(nutzer.path("konten", a + ".json"), encoding="utf-8")).get("rechte", [])
        except (OSError, ValueError):
            kann = []
        wer = [n for n in names if any(r in d["nutzer"][n].get("rechte", []) for r in (f"mail:{a}", f"kalender:{a}", f"drive:{a}"))]
        g.append(f'<tr><td>{e(a)}</td><td>{e(", ".join(kann))}</td><td>{e(", ".join(wer) or "–")}</td><td>'
                 + form("google_weg", f'<input type="hidden" name="adresse" value="{e(a)}"><button class="x">Entfernen</button>', confirm=f"{a} entfernen und bei Google abmelden?") + '</td></tr>')
    out.append('<section id="google"><h2>Google-Konten</h2><table><tr><th>Konto</th><th>kann</th><th>freigegeben für</th><th></th></tr>' + "".join(g) + '</table>'
               + form("google_neu", '<div class="row"><input type="email" name="adresse" placeholder="adresse@gmail.com" required>'
                      f'<label><input type="checkbox" name="mail" checked> Mail</label><label><input type="checkbox" name="kalender" checked> Kalender</label>'
                      f'<label><input type="checkbox" name="drive" checked> Drive/Docs/Sheets</label> für <select name="fuer">{opts}</select>'
                      '<button>Bei Google anmelden →</button></div>', cls="") +
               '<p class="mut">Du wirst zu Google geleitet. Mit dem Konto anmelden, bei „Google hat diese App nicht überprüft“ → Erweitert → Weiter, Rechte erlauben. '
               'Danach landest du wieder hier. Mails werden nie gesendet; Kalender: lesen, eintragen, einladen; Drive: alles lesen, Tabellen/Docs bearbeiten, neue anlegen – nie löschen oder teilen. '
               'Ein schon eingerichtetes Konto einfach noch einmal anmelden, um Rechte zu ergänzen.</p></section>')

    # Datenbanken
    db = []
    for n in nutzer.databases():
        try:
            u = urllib.parse.urlparse(json.load(open(nutzer.path("datenbanken", n + ".json"), encoding="utf-8"))["url"])
            wo = f"{u.username}@{u.hostname}/{u.path.lstrip('/')}"
        except (OSError, ValueError, KeyError):
            wo = "?"
        wer = [x for x in names if f"db:{n}" in d["nutzer"][x].get("rechte", [])]
        db.append(f'<tr><td>{e(n)}</td><td class="mut">{e(wo)}</td><td>{e(", ".join(wer) or "–")}</td><td>'
                  + form("db_test", f'<input type="hidden" name="dbname" value="{e(n)}"><button class="l">Testen</button>') + " "
                  + form("db_weg", f'<input type="hidden" name="dbname" value="{e(n)}"><button class="x">Entfernen</button>', confirm=f"Datenbank {n} entfernen?") + '</td></tr>')
    out.append('<section id="db"><h2>Datenbanken (nur lesen)</h2><table><tr><th>Name</th><th>Zugang</th><th>freigegeben für</th><th></th></tr>' + "".join(db) + '</table>'
               + form("db_neu", '<div class="row"><input name="dbname" placeholder="name (z. B. heroku)" pattern="[a-z][a-z0-9_-]{1,23}" required>'
                      '<input type="password" name="url" placeholder="postgres://nutzer:passwort@host:5432/db" size="38" required>'
                      f' für <select name="fuer">{opts}</select><button>Testen und speichern</button></div>', cls="") +
               '<p class="mut">Am besten ein Zugang, der nur lesen darf. home-mcp liest zusätzlich immer in einer read-only-Sitzung und nimmt nur SELECT/WITH/… an.</p></section>')

    # GitLab
    gl = "nicht eingerichtet"
    if os.path.exists(nutzer.path("gitlab.json")):
        gl = "eingerichtet · freigegeben für: " + (", ".join(n for n in names if "gitlab" in d["nutzer"][n].get("rechte", [])) or "–")
    out.append(f'<section id="gitlab"><h2>GitLab (gitlab.com, nur lesen)</h2><p>{e(gl)}</p>'
               + form("gitlab_test", '<button class="l">Token prüfen</button>') + " "
               + (form("gitlab_weg", '<button class="x">Entfernen</button>', confirm="GitLab-Token entfernen?") if os.path.exists(nutzer.path("gitlab.json")) else "")
               + form("gitlab_neu", '<div class="row"><input type="password" name="token" placeholder="glpat-… (nur read_api)" size="30" required>'
                      f' für <select name="fuer">{opts}</select><button>Prüfen und speichern</button></div>', cls="") +
               '<p class="mut">Token mit Schreibrechten werden abgelehnt.</p></section>')

    # Besucherstatistik
    seiten = gc_load()
    st = ("freigegeben für: " + (", ".join(n for n in names if "statistik" in d["nutzer"][n].get("rechte", [])) or "–")) if seiten else "nicht eingerichtet"
    rows = "".join(f'<li>{e(x["name"])} · <span class="mut">{e(x["url"])}</span> '
                   + form("statistik_test", f'<input type="hidden" name="seite" value="{e(x["name"])}"><button class="l">Prüfen</button>') + " "
                   + form("statistik_weg", f'<input type="hidden" name="seite" value="{e(x["name"])}"><button class="x">Entfernen</button>',
                          confirm=f'Statistik für {x["name"]} entfernen?') + "</li>" for x in seiten)
    out.append(f'<section id="statistik"><h2>Besucherstatistik (GoatCounter, nur lesen)</h2><p>{e(st)}</p>'
               + (f"<ul>{rows}</ul>" if rows else "")
               + form("statistik_neu", '<div class="row"><input name="seite" placeholder="example.com" size="16" required>'
                      '<input name="url" placeholder="https://name.goatcounter.com" size="28" required>'
                      '<input type="password" name="token" placeholder="API-Token (nur Statistik lesen)" size="24" required>'
                      f' für <select name="fuer">{opts}</select><button>Prüfen und speichern</button></div>', cls="") +
               '<p class="mut">Token in GoatCounter unter Benutzer → API anlegen, nur „Read statistics“. Gleicher Name ersetzt den Eintrag.</p></section>')

    # Slack
    sl = "nicht eingerichtet"
    if os.path.exists(nutzer.path("slack.json")):
        sl = "eingerichtet · freigegeben für: " + (", ".join(n for n in names if "slack" in d["nutzer"][n].get("rechte", [])) or "–")
    out.append(f'<section id="slack"><h2>Slack (nur lesen)</h2><p>{e(sl)}</p>'
               + (form("slack_test", '<button class="l">Token prüfen</button>') + " "
                  + form("slack_weg", '<button class="x">Entfernen</button>', confirm="Slack-Token entfernen?") if os.path.exists(nutzer.path("slack.json")) else "")
               + slack_wl_forms(d, names, form)
               + form("slack_neu", '<div class="row"><input type="password" name="token" placeholder="xoxp-… (nur Lese-Bereiche)" size="30" required>'
                      f' für <select name="fuer">{opts}</select><button>Prüfen und speichern</button></div>', cls="") +
               '<p class="mut">Slack-App mit Nutzer-Token und nur diesen Bereichen: channels:history, channels:read, groups:history, groups:read, '
               'im:history, im:read, mpim:history, mpim:read, users:read, search:read. Token mit Schreib-Bereichen werden abgelehnt; '
               'home-mcp ruft zusätzlich nur lesende Methoden auf.</p></section>')

    # Protokoll
    log = "\n".join(reversed(mcp.AUDIT[-150:])) or "Noch nichts seit dem letzten Neustart."
    out.append(f'<section id="log"><h2>Protokoll (seit Neustart, neueste oben)</h2><pre>{e(log)}</pre>'
               '<p class="mut">Vollständig auf dem Pi: journalctl -u home-mcp</p></section>')
    return page("home-mcp · Verwaltung", "".join(out))


def slack_wl_forms(d: dict, names: list, form) -> str:
    """Je Nutzer mit Slack-Recht: Kanal-Whitelist als Auswahlliste mit Suchfeld."""
    wer = [n for n in names if "slack" in d["nutzer"][n].get("rechte", [])]
    if not wer or not os.path.exists(nutzer.path("slack.json")):
        return ""
    try:
        tok = json.load(open(nutzer.path("slack.json"), encoding="utf-8"))["token"]
        chans = sorted((c for c in mcp.slack_channels(tok) if not (c.get("is_im") or c.get("is_mpim"))), key=lambda c: (c.get("name") or "").lower())
    except Exception as ex:  # noqa: BLE001
        return f'<p class="msg err">Slack-Kanäle nicht lesbar: {e(ex)}</p>'
    out = []
    for n in wer:
        u = d["nutzer"][n]
        wl = set(u.get("slack_kanaele") or [])
        leer = "alle Kanäle" if not u.get("bot") else "keine Kanäle (nur Direktnachrichten, Erwähnungen, eigene)"
        boxes = "".join(f'<label class="r sk"><input type="checkbox" name="kanal" value="{e(c["id"])}"{" checked" if c["id"] in wl else ""}> '
                        f'#{e(c.get("name"))}{" 🔒" if c.get("is_private") else ""}</label>'
                        for c in sorted(chans, key=lambda c: (c["id"] not in wl, (c.get("name") or "").lower())))
        out.append(f'<details{" open" if u.get("bot") else ""}><summary><b>{e(n)}</b>: {len(wl) or "keine"} Kanäle freigegeben'
                   f'{"" if wl else " → " + leer}</summary>'
                   + form("slack_wl", f'<input type="hidden" name="name" value="{e(n)}"><div class="row">'
                          '<input type="search" placeholder="Kanal suchen …" oninput="var q=this.value.toLowerCase();'
                          'this.form.querySelectorAll(\'.sk\').forEach(function(l){l.style.display=l.textContent.toLowerCase().indexOf(q)>=0?\'\':\'none\'})">'
                          '<button>Whitelist speichern</button></div>'
                          f'<div style="max-height:280px;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:6px 10px">{boxes}</div>', cls="")
                   + '</details>')
    return ('<h2 style="margin-top:14px">Kanal-Whitelist</h2>' + "".join(out) +
            '<p class="mut">Direktnachrichten an dich, Erwähnungen und deine eigenen Nachrichten (slack_fuer_mich) gehen unabhängig davon immer. '
            'Ohne Whitelist sehen Menschen alle Kanäle, Bots keinen.</p>')


LOGIN = """<h1>home-mcp · Verwaltung</h1><section><form method="post" action="/login">
<div class="row"><input name="name" placeholder="Name" autocomplete="username" autofocus required>
<input type="password" name="pw" placeholder="Passwort" autocomplete="current-password" required><button>Anmelden</button></div></form>
<p class="mut">Nur für Admins. Erreichbar nur über den SSH-Tunnel auf 127.0.0.1.</p>{msg}</section>"""


# ── Aktionen ───────────────────────────────────────────────────────

def act(s: dict, f: dict) -> str | None:
    """Führt eine Aktion aus; Rückgabe: Weiterleitung (Google) oder None. Meldung in s['msg']."""
    was = f.get("was", [""])[0]
    one = lambda k: (f.get(k) or [""])[0].strip()  # noqa: E731
    me = s["user"]
    name = one("name").lower()
    if was == "abmelden":
        with _lock:
            _sessions.pop(s["sid"], None)
        return "/"
    if was == "neu":
        if name in nutzer.load()["nutzer"]:
            raise ValueError(f"{name} gibt es schon.")
        nutzer.set_user(name, pw=one("pw"), admin=bool(one("admin")), rechte=[])
        s["msg"] = f"{name} angelegt – jetzt Rechte anhaken."
    elif was == "bot_neu":
        if name in nutzer.load()["nutzer"]:
            raise ValueError(f"{name} gibt es schon.")
        nutzer.set_user(name, rechte=[], bot=True)
        s["msg"] = f"Bot {name} angelegt – jetzt Rechte anhaken und Schlüssel erzeugen."
    elif was == "key_neu":
        key = nutzer.key_new(name, one("art"), one("label"))
        s["msg"] = (f"Neuer Schlüssel für {name} ({'Bot/Werkzeuge' if one('art') == 'mcp' else 'App/Freigaben'}) – JETZT kopieren, er wird nie wieder angezeigt:  {key}")
    elif was == "key_weg":
        nutzer.key_drop(name, one("kid"))
        s["msg"] = f"Schlüssel {one('kid')} von {name} widerrufen."
    elif was in ("freigabe_ja", "freigabe_nein"):
        f = freigaben.entscheiden(one("fid"), was == "freigabe_ja", f"verwaltung:{me}", mcp.freigabe_ausfuehren)
        mcp.AUDIT.append(f"{time.strftime('%d.%m. %H:%M:%S')} [{me}] freigabe {f['id']} {'ja' if was == 'freigabe_ja' else 'nein'} → {f['status']}")
        s["msg"] = f"{f['id']}: {f['status']}" + (f" – {f['ergebnis']}" if f.get("ergebnis") else "")
    elif was == "slack_neu":
        tok = one("token")
        info = slack_check(tok)
        write_secret(nutzer.path("slack.json"), {"token": tok})
        mcp._slack_users.clear()
        mcp._slack_chans.clear()
        nutzer.grant(one("fuer"), "slack")
        s["msg"] = f"Slack gespeichert ✓ {info['user']} @ {info['team']} · {', '.join(info['scopes'])}"
    elif was == "slack_wl":
        ids = {c["id"] for c in mcp.slack_channels(json.load(open(nutzer.path("slack.json"), encoding="utf-8"))["token"])}
        sel = [k for k in f.get("kanal", []) if k in ids]
        nutzer.set_field(name, "slack_kanaele", sel)
        s["msg"] = f"Slack-Whitelist von {name}: {len(sel)} Kanäle – wirkt sofort."
    elif was == "slack_test":
        info = slack_check(json.load(open(nutzer.path("slack.json"), encoding="utf-8"))["token"])
        s["msg"] = f"Slack ✓ {info['user']} @ {info['team']} · {', '.join(info['scopes'])}"
    elif was == "slack_weg":
        if os.path.exists(nutzer.path("slack.json")):
            os.remove(nutzer.path("slack.json"))
        mcp._slack_users.clear()
        mcp._slack_chans.clear()
        nutzer.drop_right_everywhere("slack")
        s["msg"] = "Slack-Token entfernt – in Slack auch widerrufen (App → OAuth → Revoke)."
    elif was == "rechte":
        valid = {r for r, _ in nutzer.all_rights()}
        old = [r for r in nutzer.load()["nutzer"][name].get("rechte", []) if r not in valid]  # Rechte auf fehlende Ressourcen behalten
        nutzer.set_user(name, rechte=old + [r for r in f.get("recht", []) if r in valid])
        nutzer.set_field(name, "kalender_nur_haupt", [a for a in f.get("nurhaupt", []) if a in nutzer.accounts()])
        s["msg"] = f"Rechte von {name} gespeichert – wirkt sofort (in Claude: neuer Chat)."
    elif was == "passwort":
        nutzer.set_user(name, pw=one("pw"))
        n = mcp.revoke_user(name) if name != me else 0
        s["msg"] = f"Passwort von {name} geändert" + (f", {n} Zugänge abgemeldet." if n else ".")
    elif was in ("sperren", "entsperren"):
        if name == me:
            raise ValueError("Dich selbst kannst du nicht sperren.")
        nutzer.set_user(name, gesperrt=(was == "sperren"))
        n = mcp.revoke_user(name) if was == "sperren" else 0
        s["msg"] = f"{name} {'gesperrt, ' + str(n) + ' Zugänge abgemeldet' if was == 'sperren' else 'entsperrt'}."
    elif was == "admin":
        if name == me:
            raise ValueError("Dir selbst kannst du Admin nicht entziehen.")
        u = nutzer.load()["nutzer"][name]
        nutzer.set_user(name, admin=not u.get("admin"))
        s["msg"] = f"{name} ist {'jetzt' if not u.get('admin') else 'kein'} Admin."
    elif was == "loeschen":
        if name == me:
            raise ValueError("Dich selbst kannst du nicht löschen.")
        n = mcp.revoke_user(name)
        nutzer.delete_user(name)
        s["msg"] = f"{name} gelöscht, {n} Zugänge abgemeldet."
    elif was == "abmelden_alle":
        n = mcp.revoke_user(name)
        s["msg"] = f"{name}: {n} Zugänge abgemeldet – Claude fragt beim nächsten Mal wieder nach dem Passwort."
    elif was == "google_neu":
        addr = one("adresse").lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", addr):
            raise ValueError("Bitte eine Mail-Adresse angeben.")
        fuer = one("fuer")
        if fuer not in nutzer.load()["nutzer"]:
            raise ValueError("Unbekannter Nutzer.")
        try:
            c = client_conf()
        except OSError:
            raise ValueError("client.json fehlt auf dem Pi (OAuth-Client aus der Google Cloud Console).") from None
        verifier, state = secrets.token_urlsafe(48), secrets.token_urlsafe(24)
        s["google"] = {"verifier": verifier, "state": state, "addr": addr, "kalender": bool(one("kalender")), "fuer": fuer, "exp": time.time() + 900}
        scopes = (MAIL_SCOPES if one("mail") else []) + (CAL_SCOPES if one("kalender") else []) + (DRIVE_SCOPES if one("drive") else [])
        if not scopes:
            raise ValueError("Mindestens Mail, Kalender oder Drive auswählen.")
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
            "client_id": c["client_id"], "redirect_uri": REDIRECT, "response_type": "code", "scope": " ".join(scopes),
            "access_type": "offline", "prompt": "consent", "login_hint": addr, "state": state,
            "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode(),
            "code_challenge_method": "S256"})
    elif was == "google_weg":
        addr = one("adresse")
        if addr not in nutzer.accounts():
            raise ValueError("Konto nicht gefunden.")
        p = nutzer.path("konten", addr + ".json")
        try:  # bei Google widerrufen
            rt = json.load(open(p, encoding="utf-8"))["refresh_token"]
            urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/revoke", data=urllib.parse.urlencode({"token": rt}).encode()), timeout=15)
        except Exception:  # noqa: BLE001
            pass
        os.remove(p)
        mcp._tokens.pop(addr, None)
        for k in ("mail", "kalender", "drive"):
            nutzer.drop_right_everywhere(f"{k}:{addr}")
        s["msg"] = f"{addr} entfernt und bei Google abgemeldet."
    elif was == "db_neu":
        n = one("dbname").lower()
        if not nutzer.NAME_RE.match(n):
            raise ValueError("Name: Kleinbuchstaben, Ziffern, - oder _.")
        url = one("url")
        u = urllib.parse.urlparse(url)
        if u.scheme not in ("postgres", "postgresql") or not (u.hostname and u.username and u.path.strip("/")):
            raise ValueError("Das sieht nicht nach postgres://nutzer:passwort@host:port/datenbank aus.")
        info = pg_check(url)
        write_secret(nutzer.path("datenbanken", n + ".json"), {"url": url})
        nutzer.grant(one("fuer"), f"db:{n}")
        s["msg"] = f"Datenbank „{n}“ gespeichert ✓ {info}" + (" · ACHTUNG: Zugang hat Schreibrechte (home-mcp liest trotzdem nur)." if "Schreibrechte: keine" not in info else "")
    elif was == "db_test":
        n = one("dbname")
        url = json.load(open(nutzer.path("datenbanken", n + ".json"), encoding="utf-8"))["url"]
        s["msg"] = f"„{n}“ ✓ {pg_check(url)}"
    elif was == "db_weg":
        n = one("dbname")
        if n in nutzer.databases():
            os.remove(nutzer.path("datenbanken", n + ".json"))
            nutzer.drop_right_everywhere(f"db:{n}")
        s["msg"] = f"Datenbank „{n}“ entfernt."
    elif was == "gitlab_neu":
        tok = one("token")
        info = gl_check(tok)
        write_secret(nutzer.path("gitlab.json"), {"token": tok, "url": "https://gitlab.com"})
        mcp._gl_me.clear()
        nutzer.grant(one("fuer"), "gitlab")
        s["msg"] = f"GitLab gespeichert ✓ {info['user']} · {', '.join(info['scopes'])} · läuft ab: {info['expires'] or 'nie'}"
    elif was == "gitlab_test":
        tok = json.load(open(nutzer.path("gitlab.json"), encoding="utf-8"))["token"]
        info = gl_check(tok)
        s["msg"] = f"GitLab ✓ {info['user']} · {', '.join(info['scopes'])} · läuft ab: {info['expires'] or 'nie'}"
    elif was == "gitlab_weg":
        if os.path.exists(nutzer.path("gitlab.json")):
            os.remove(nutzer.path("gitlab.json"))
        mcp._gl_me.clear()
        nutzer.drop_right_everywhere("gitlab")
        s["msg"] = "GitLab-Token entfernt – bei gitlab.com auch widerrufen (Access tokens → Revoke)."
    elif was == "statistik_neu":
        name, url, tok = one("seite").strip().lower(), one("url").strip().rstrip("/"), one("token").strip()
        if not name or not tok:
            raise ValueError("Name und Token fehlen.")
        n = gc_check(url, tok)
        seiten = [x for x in gc_load() if x["name"] != name] + [{"name": name, "url": url, "token": tok}]
        write_secret(nutzer.path("goatcounter.json"), {"seiten": seiten})
        nutzer.grant(one("fuer"), "statistik")
        s["msg"] = f"Statistik für {name} gespeichert ✓ {n} Besuche in den letzten 7 Tagen"
    elif was == "statistik_test":
        x = next((x for x in gc_load() if x["name"] == one("seite")), None)
        if not x:
            raise ValueError("Seite nicht gefunden.")
        s["msg"] = f"Statistik {x['name']} ✓ {gc_check(x['url'], x['token'])} Besuche in den letzten 7 Tagen"
    elif was == "statistik_weg":
        seiten = [x for x in gc_load() if x["name"] != one("seite")]
        if seiten:
            write_secret(nutzer.path("goatcounter.json"), {"seiten": seiten})
        else:
            if os.path.exists(nutzer.path("goatcounter.json")):
                os.remove(nutzer.path("goatcounter.json"))
            nutzer.drop_right_everywhere("statistik")
        s["msg"] = f"Statistik für {one('seite')} entfernt – den Token in GoatCounter auch löschen (Benutzer → API)."
    else:
        raise ValueError("Unbekannte Aktion.")
    print(f"verwaltung [{me}] {was} {name or one('adresse') or one('dbname') or one('fid')}", flush=True)
    return None


def google_back(s: dict, q: dict) -> None:
    g = s.pop("google", None)
    if not g or g["exp"] < time.time() or q.get("state") != g["state"]:
        raise ValueError("Google-Anmeldung abgelaufen oder unbekannt – bitte noch einmal starten.")
    if q.get("error"):
        raise ValueError(f"Google: {q['error']}")
    c = client_conf()
    data = urllib.parse.urlencode({"code": q.get("code", ""), "client_id": c["client_id"], "client_secret": c["client_secret"],
                                   "redirect_uri": REDIRECT, "grant_type": "authorization_code", "code_verifier": g["verifier"]}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/token", data=data), timeout=30) as r:
            o = json.loads(r.read())
    except urllib.error.HTTPError as ex:
        raise ValueError(f"Google lehnt ab ({ex.code}): {ex.read()[:200].decode(errors='replace')}") from None
    if "refresh_token" not in o:
        raise ValueError("Google hat keinen dauerhaften Zugang geliefert – bitte noch einmal.")
    # Welches Konto wurde tatsächlich gewählt? (Kann vom Vorschlag abweichen)
    addr = g["addr"]
    try:
        req = urllib.request.Request("https://gmail.googleapis.com/gmail/v1/users/me/profile", headers={"Authorization": "Bearer " + o["access_token"]})
        with urllib.request.urlopen(req, timeout=20) as r:
            addr = json.loads(r.read()).get("emailAddress", addr).lower()
    except Exception:  # noqa: BLE001
        pass
    granted = o.get("scope", "")
    rechte = ((["mail"] if "gmail.readonly" in granted else []) + (["kalender"] if "calendar.events" in granted else [])
              + (["drive"] if "drive.readonly" in granted else []))
    if "gmail.readonly" not in granted:  # ohne Gmail-Recht klappt die Profilabfrage oben nicht – Adresse über Drive holen
        try:
            req = urllib.request.Request("https://www.googleapis.com/drive/v3/about?fields=user(emailAddress)",
                                         headers={"Authorization": "Bearer " + o["access_token"]})
            with urllib.request.urlopen(req, timeout=20) as r:
                addr = (json.loads(r.read()).get("user", {}).get("emailAddress") or addr).lower()
        except Exception:  # noqa: BLE001
            pass
    write_secret(nutzer.path("konten", addr + ".json"), {"refresh_token": o["refresh_token"], "rechte": rechte})
    mcp._tokens.pop(addr, None)
    for k in rechte:
        nutzer.grant(g["fuer"], f"{k}:{addr}")
    print(f"verwaltung [{s['user']}] google {addr} → {g['fuer']} ({', '.join(rechte)})", flush=True)
    s["msg"] = f"{addr} eingerichtet ✓ ({', '.join(rechte) or 'keine Rechte?'}) und für {g['fuer']} freigegeben."


# ── HTTP ───────────────────────────────────────────────────────────

class Admin(BaseHTTPRequestHandler):
    server_version = "home-mcp-verwaltung"
    sys_version = ""

    def _out(self, code: int, body: str = "", location: str | None = None, cookie: str | None = None):
        data = body.encode()
        self.send_response(code)
        if location:
            self.send_header("Location", location)
        if cookie is not None:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(data)

    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        if host == f"localhost:{PORT}":
            self._out(302, location=ORIGIN + self.path)  # Google-Weiterleitung braucht 127.0.0.1
            return False
        if host != f"127.0.0.1:{PORT}":
            self._out(403, page("Nein", "<p>Nur über http://127.0.0.1:%d erreichbar.</p>" % PORT))
            return False
        return True

    def _session(self) -> dict | None:
        m = re.search(r"(?:^|;\s*)hmv=([\w-]+)", self.headers.get("Cookie", ""))
        with _lock:
            now = time.time()
            for k in [k for k, v in _sessions.items() if v["exp"] < now]:
                _sessions.pop(k)
            s = _sessions.get(m.group(1)) if m else None
        if s and not (nutzer.get(s["user"]) or {}).get("admin"):
            return None  # inzwischen gesperrt oder kein Admin mehr
        return s

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return urllib.parse.parse_qs(self.rfile.read(n).decode() if 0 < n < 200_000 else "", keep_blank_values=True)

    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return
        u = urllib.parse.urlparse(self.path)
        s = self._session()
        if not s:
            return self._out(200, page("Anmelden", LOGIN.format(msg="")))
        q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        if u.path == "/" and ("code" in q or "error" in q) and "state" in q:
            try:
                google_back(s, q)
            except Exception as ex:  # noqa: BLE001
                s["msg"] = "!" + str(ex)
            return self._out(303, location="/#google")
        if u.path != "/":
            return self._out(404, page("?", "<p>Gibt es nicht.</p>"))
        self._out(200, render(s))

    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return
        origin = self.headers.get("Origin")
        if origin and origin not in (ORIGIN, "null"):
            return self._out(403, page("Nein", "<p>Fremde Herkunft.</p>"))
        f = self._body()
        path = self.path.split("?")[0]
        if path == "/login":
            u = nutzer.check_pw((f.get("name") or [""])[0], (f.get("pw") or [""])[0])
            if not u or not u.get("admin"):
                print(f"verwaltung anmeldung FEHLGESCHLAGEN „{(f.get('name') or [''])[0][:30]}“", flush=True)
                return self._out(200, page("Anmelden", LOGIN.format(msg='<p class="msg err">Name/Passwort falsch oder kein Admin.</p>')))
            sid = secrets.token_urlsafe(32)
            with _lock:
                _sessions[sid] = {"sid": sid, "user": u["name"], "csrf": secrets.token_urlsafe(24), "exp": time.time() + SESSION_TTL}
            print(f"verwaltung anmeldung ok: {u['name']}", flush=True)
            # SameSite=Lax, damit die Rückkehr von Google (Top-Level-GET) die Sitzung mitbringt; Änderungen brauchen trotzdem das CSRF-Token
            return self._out(303, location="/", cookie=f"hmv={sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age={SESSION_TTL}")
        s = self._session()
        if not s:
            return self._out(303, location="/")
        if path != "/aktion" or not secrets.compare_digest((f.get("csrf") or [""])[0], s["csrf"]):
            return self._out(403, page("Nein", "<p>Ungültige Anfrage – Seite neu laden.</p>"))
        try:
            go = act(s, f)
        except Exception as ex:  # noqa: BLE001
            s["msg"] = "!" + str(ex)
            go = None
        if go and go.startswith("https://accounts.google.com/"):
            return self._out(303, location=go)
        anchor = {"google_weg": "#google", "db_neu": "#db", "db_test": "#db", "db_weg": "#db", "gitlab_neu": "#gitlab",
                  "gitlab_test": "#gitlab", "gitlab_weg": "#gitlab", "slack_neu": "#slack", "slack_test": "#slack", "slack_wl": "#slack", "slack_weg": "#slack",
                  "statistik_neu": "#statistik", "statistik_test": "#statistik", "statistik_weg": "#statistik",
                  "freigabe_ja": "#freigaben", "freigabe_nein": "#freigaben"}.get((f.get("was") or [""])[0], "#nutzer")
        self._out(303, location=(go or "/") + ("" if go else anchor))

    def log_message(self, fmt, *args):
        pass  # Aktionen werden oben gezielt protokolliert (ohne Passwörter/Token)


def start(mcp_module) -> None:
    global mcp
    mcp = mcp_module
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), Admin)
    threading.Thread(target=srv.serve_forever, daemon=True, name="verwaltung").start()
