#!/usr/bin/env python3
"""
Einrichten von home-mcp – interaktiv auf dem Pi, in DEINEM Terminal (Passwörter und Codes laufen nicht über einen Chat).
Bequemer geht fast alles über die Verwaltungsseite (ssh -L 8791:127.0.0.1:8791 raspi → http://127.0.0.1:8791);
das hier bleibt der Weg, wenn man sich dort ausgesperrt hat:
  sudo -u homemcp python3 /opt/home-mcp/einrichten.py passwort [name]      (Passwort setzen; neuer Name = neuer Admin)
  sudo -u homemcp python3 /opt/home-mcp/einrichten.py konto privat@example.com
  sudo -u homemcp python3 /opt/home-mcp/einrichten.py konto ich@example.com --kalender [--drive]
  sudo -u homemcp python3 /opt/home-mcp/einrichten.py datenbank [name]  (Postgres-Zugang, nur lesen; Standardname heroku)
  sudo -u homemcp python3 /opt/home-mcp/einrichten.py gitlab            (Personal Access Token, nur Bereich read_api)
Konten, Datenbanken und GitLab werden dem festen-Schlüssel-Nutzer (meist admin) freigegeben, mit --fuer NAME einem anderen.
Google-Anmeldung: Link im Browser öffnen, Konto wählen, erlauben. Danach lädt der Browser eine Seite, die nicht geht
(http://127.0.0.1…) – das ist richtig: die komplette Adresse aus der Adresszeile kopieren und hier einfügen.
"""
import base64
import getpass
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import nutzer  # noqa: E402

HOME = os.environ.get("HOME_MCP_HOME", "/srv/home-mcp")
REDIRECT = "http://127.0.0.1:8765/"
MAIL = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose"]
CAL = ["https://www.googleapis.com/auth/calendar.readonly", "https://www.googleapis.com/auth/calendar.events"]
DRIVE = ["https://www.googleapis.com/auth/drive.readonly", "https://www.googleapis.com/auth/drive.file",
         "https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/documents"]


def fuer() -> str:
    a = sys.argv
    name = a[a.index("--fuer") + 1] if "--fuer" in a and a.index("--fuer") + 1 < len(a) else nutzer.token_owner()
    if not name or name not in nutzer.load()["nutzer"]:
        sys.exit(f"Nutzer „{name}“ gibt es nicht – zuerst: einrichten.py passwort {name or 'admin'}")
    return name


def passwort(name: str | None):
    d = nutzer.load()
    name = (name or nutzer.token_owner() or "admin").lower()
    neu = name not in d["nutzer"]
    pw = getpass.getpass(f"Neues Passwort für {name} (Anmeldung in Claude, mind. 12 Zeichen): ")
    if len(pw) < 12 or pw != getpass.getpass("Wiederholen: "):
        sys.exit("Zu kurz oder unterschiedlich.")
    nutzer.set_user(name, pw=pw, admin=True if neu else None, gesperrt=False)
    print(f"Passwort für {name} gespeichert ✓ (nur als Hash)" + (" – neuer Admin angelegt." if neu else "."))
    print("Hinweis: bestehende Claude-Verbindungen bleiben angemeldet; abmelden geht auf der Verwaltungsseite.")


def konto(addr: str, kalender: bool):
    try:
        c = json.load(open(os.path.join(HOME, "client.json")))
    except OSError:
        sys.exit(f"{HOME}/client.json fehlt – OAuth-Client aus der Google Cloud Console (Desktop-App) dorthin kopieren.")
    c = c.get("installed") or c.get("web") or c
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    scopes = MAIL + (CAL if kalender else []) + (DRIVE if "--drive" in sys.argv else [])
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode({
        "client_id": c["client_id"], "redirect_uri": REDIRECT, "response_type": "code", "scope": " ".join(scopes),
        "access_type": "offline", "prompt": "consent", "login_hint": addr, "code_challenge": challenge, "code_challenge_method": "S256"})
    print("\n1. Diesen Link im Browser öffnen und mit", addr, "anmelden:\n\n" + url + "\n")
    print("2. „Google hat diese App nicht überprüft“ → Erweitert → Weiter (es ist deine eigene App). Rechte erlauben.")
    print("3. Der Browser zeigt danach eine Fehlerseite (127.0.0.1) – die ganze Adresse aus der Adresszeile hier einfügen:\n")
    back = input("> ").strip()
    code = urllib.parse.parse_qs(urllib.parse.urlparse(back).query).get("code", [back])[0]
    data = urllib.parse.urlencode({"code": code, "client_id": c["client_id"], "client_secret": c["client_secret"],
                                   "redirect_uri": REDIRECT, "grant_type": "authorization_code", "code_verifier": verifier}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request("https://oauth2.googleapis.com/token", data=data), timeout=30) as r:
            o = json.loads(r.read())
    except urllib.error.HTTPError as e:
        sys.exit(f"Google lehnt ab ({e.code}): {e.read()[:300].decode(errors='replace')}")
    if "refresh_token" not in o:
        sys.exit("Kein Refresh-Token erhalten – bitte noch einmal (prompt=consent sorgt normalerweise dafür).")
    granted = o.get("scope", "")
    rechte = ((["mail"] if "gmail.readonly" in granted else []) + (["kalender"] if "calendar.events" in granted else [])
              + (["drive"] if "drive.readonly" in granted else []))
    os.makedirs(os.path.join(HOME, "konten"), mode=0o700, exist_ok=True)
    nutzer._write_json(os.path.join(HOME, "konten", addr + ".json"), {"refresh_token": o["refresh_token"], "rechte": rechte})
    wer = fuer()
    for k in rechte:
        nutzer.grant(wer, f"{k}:{addr}")
    print(f"\n{addr} eingerichtet ✓ – Rechte: {', '.join(rechte) or 'keine?'} – freigegeben für {wer}")


def datenbank(name: str):
    if not nutzer.NAME_RE.match(name):
        sys.exit("Name: Kleinbuchstaben, Ziffern, - oder _.")
    print("Heroku-Zugang (nur lesen) als URL: postgres://nur_lesen:PASSWORT@HOST:5432/DATENBANK")
    print("Die Eingabe wird nicht angezeigt.")
    url = getpass.getpass("URL: ").strip()
    u = urllib.parse.urlparse(url)
    if u.scheme not in ("postgres", "postgresql") or not (u.hostname and u.username and u.password and u.path.strip("/")):
        sys.exit("Das sieht nicht nach postgres://benutzer:passwort@host:port/datenbank aus.")
    env = {"PATH": "/usr/bin:/bin", "PGHOST": u.hostname, "PGPORT": str(u.port or 5432), "PGUSER": urllib.parse.unquote(u.username),
           "PGPASSWORD": urllib.parse.unquote(u.password), "PGDATABASE": u.path.lstrip("/"), "PGSSLMODE": "require",
           "PGCONNECT_TIMEOUT": "10", "PGOPTIONS": "-c default_transaction_read_only=on"}
    sql = ("SELECT current_user || ' auf ' || current_database() || ' · Server ' || current_setting('server_version') || "
           "' · Schreibrechte: ' || coalesce((SELECT string_agg(DISTINCT privilege_type, ', ') FROM information_schema.role_table_grants "
           "WHERE grantee = current_user AND privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE')), 'keine')")
    import subprocess
    r = subprocess.run(["psql", "-X", "-q", "-A", "-t", "-c", sql], env=env, capture_output=True, text=True, timeout=30)
    if r.returncode:
        sys.exit("Verbindung klappt nicht: " + r.stderr.strip().replace(env["PGPASSWORD"], "***")[:500])
    print("Verbindung ✓", r.stdout.strip())
    if "Schreibrechte: keine" not in r.stdout:
        print("ACHTUNG: dieser Zugang hat Schreibrechte – home-mcp liest trotzdem nur (read-only-Sitzung), besser wäre ein reiner Lesezugang.")
    os.makedirs(os.path.join(HOME, "datenbanken"), mode=0o700, exist_ok=True)
    nutzer._write_json(os.path.join(HOME, "datenbanken", name + ".json"), {"url": url})
    wer = fuer()
    nutzer.grant(wer, f"db:{name}")
    print(f"Gespeichert ✓ als „{name}“, freigegeben für {wer}. Ein Neustart von home-mcp ist nicht nötig.")


def gitlab():
    print("GitLab → Profil → Preferences → Access tokens → „Add new token“: Name „home-mcp“, Ablaufdatum setzen,")
    print("als Bereich NUR „read_api“ anhaken. Den Token hier einfügen (Eingabe wird nicht angezeigt).")
    tok = getpass.getpass("Token: ").strip()
    url = "https://gitlab.com"
    def get(path):
        req = urllib.request.Request(url + "/api/v4" + path, headers={"PRIVATE-TOKEN": tok})
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    try:
        me = get("/user")
        info = get("/personal_access_tokens/self")
    except urllib.error.HTTPError as e:
        sys.exit(f"GitLab lehnt den Token ab ({e.code}).")
    scopes = info.get("scopes", [])
    print(f"Token ✓ – {me.get('username')} · Bereiche: {', '.join(scopes)} · läuft ab: {info.get('expires_at') or 'nie'}")
    extra = [s for s in scopes if s not in ("read_api", "read_user", "read_repository")]
    if extra:
        sys.exit(f"Abgebrochen: der Token hat Schreibrechte ({', '.join(extra)}). Bitte einen neuen NUR mit read_api anlegen.")
    nutzer._write_json(os.path.join(HOME, "gitlab.json"), {"token": tok, "url": url})
    wer = fuer()
    nutzer.grant(wer, "gitlab")
    print(f"Gespeichert ✓ – freigegeben für {wer}. Nach einem neuen Token: home-mcp neu starten (sudo systemctl restart home-mcp).")


if __name__ == "__main__":
    nutzer.migrate()
    a = [x for i, x in enumerate(sys.argv[1:]) if x != "--fuer" and (i == 0 or sys.argv[i] != "--fuer")]
    if a[:1] == ["passwort"]:
        passwort(a[1] if len(a) > 1 else None)
    elif a[:1] == ["gitlab"]:
        gitlab()
    elif a[:1] == ["datenbank"]:
        datenbank((a[1] if len(a) > 1 else "heroku").lower())
    elif a[:1] == ["konto"] and len(a) >= 2:
        konto(a[1].strip().lower(), "--kalender" in a)
    else:
        print(__doc__)
