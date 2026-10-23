"""
Nutzer, Passwörter und Rechte von home-mcp – gemeinsam für Server, Verwaltungsseite und einrichten.py.

<HOME>/nutzer.json:
  {"nutzer": {"admin": {"pw": "salt$hash", "admin": true, "gesperrt": false,
                       "rechte": ["mail:ich@example.com", "kalender:ich@example.com", "db:heroku", "gitlab"]}},
   "token_nutzer": "admin"}          ← wem der feste Schlüssel <HOME>/token gehört (Claude Code im Tailnet)

Rechte: mail:<adresse> (lesen + Entwürfe), kalender:<adresse> (lesen, eintragen, einladen),
drive:<adresse> (Drive lesen, Sheets/Docs bearbeiten und anlegen), db:<name> (nur lesen), gitlab (nur lesen),
slack (nur lesen), statistik (Besucherstatistik GoatCounter, nur lesen).
Feinere Grenzen: "kalender_nur_haupt": [adresse] – bei diesen Konten nur der Hauptkalender;
"slack_kanaele": [kanal-id] – Slack-Whitelist (leer: Menschen alle Kanäle, Bots keinen; Direktnachrichten,
Erwähnungen und eigene Nachrichten gehen immer).
Admins dürfen zusätzlich die Verwaltungsseite benutzen.

Bots (z. B. NookBot) sind Nutzer mit "bot": true – ohne Passwort, sie melden sich mit einem Schlüssel an:
  "schluessel": [{"id": "ab12cd", "art": "mcp"|"freigabe", "hash": sha256, "name": "…", "erstellt": ts, "zuletzt": ts}]
  Schlüssel sehen so aus: hmk_<id>_<geheim>. Gespeichert wird nur der Hash, der Klartext wird einmal angezeigt.
  art "mcp": Werkzeuge benutzen (der Bot). art "freigabe": nur Freigaben entscheiden (die App) – nie umgekehrt.
  Bei Bots wartet jede Schreibaktion (Entwurf, Termin, Einladung) auf eine Freigabe, siehe freigaben.py.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

HOME = os.environ.get("HOME_MCP_HOME", "/srv/home-mcp")
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{1,23}$")
_lock = threading.RLock()
_fails: dict[str, list[float]] = {}


def path(*p) -> str:
    return os.path.join(HOME, *p)


def _write_json(p: str, d) -> None:
    with open(p + ".tmp", "w", encoding="utf-8") as f:
        json.dump(d, f, ensure_ascii=False, indent=1)
    os.chmod(p + ".tmp", 0o600)
    os.replace(p + ".tmp", p)


def load() -> dict:
    with _lock:
        try:
            with open(path("nutzer.json"), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {"nutzer": {}}
        d.setdefault("nutzer", {})
        return d


def save(d: dict) -> None:
    with _lock:
        _write_json(path("nutzer.json"), d)


def hash_pw(pw: str) -> str:
    salt = secrets.token_bytes(16)
    return salt.hex() + "$" + hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 300_000).hex()


def _pw_matches(stored: str, pw: str) -> bool:
    try:
        salt, want = stored.split("$", 1)
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 300_000).hex(), want)
    except ValueError:
        return False


def check_pw(name: str, pw: str) -> dict | None:
    """Nutzer bei richtigem Passwort, sonst None. Nach 5 Fehlern in 15 Min. (je Name und insgesamt 10) ist Pause."""
    name = (name or "").strip().lower()
    now = time.time()
    with _lock:
        for k in (name, "*"):
            _fails[k] = [t for t in _fails.get(k, []) if now - t < 900]
        if len(_fails[name]) >= 5 or len(_fails["*"]) >= 10:
            return None
        u = load()["nutzer"].get(name)
    if u and not u.get("gesperrt") and _pw_matches(u.get("pw", ""), pw or ""):
        return {"name": name, **u}
    with _lock:
        _fails[name].append(now)
        _fails["*"].append(now)
    time.sleep(1.5)
    return None


def get(name: str | None) -> dict | None:
    if not name:
        return None
    u = load()["nutzer"].get(name)
    if not u or u.get("gesperrt"):
        return None
    return {"name": name, **u}


def token_owner() -> str | None:
    d = load()
    if d.get("token_nutzer") in d["nutzer"]:
        return d["token_nutzer"]
    admins = [n for n, u in d["nutzer"].items() if u.get("admin")]
    return admins[0] if admins else None


def has(u: dict | None, right: str) -> bool:
    return bool(u) and right in u.get("rechte", [])


def resources(u: dict | None, kind: str) -> list[str]:
    """Alle Ressourcen einer Art, z. B. resources(u, 'mail') → Adressen."""
    if not u:
        return []
    return [r.split(":", 1)[1] for r in u.get("rechte", []) if r.startswith(kind + ":")]


def set_user(name: str, pw: str | None = None, admin: bool | None = None, rechte: list[str] | None = None,
             gesperrt: bool | None = None, bot: bool = False) -> None:
    name = name.strip().lower()
    if not NAME_RE.match(name):
        raise ValueError("Name: 2–24 Zeichen, Kleinbuchstaben, Ziffern, - oder _, beginnt mit Buchstabe.")
    with _lock:
        d = load()
        new = name not in d["nutzer"]
        u = d["nutzer"].setdefault(name, {"pw": "", "admin": False, "gesperrt": False, "rechte": []})
        if new and bot:
            u.update(bot=True, schluessel=[])
        if u.get("bot") and (pw is not None or admin):
            raise ValueError("Bots haben kein Passwort und sind nie Admin.")
        if pw is not None:
            if len(pw) < 12:
                raise ValueError("Passwort: mindestens 12 Zeichen.")
            u["pw"] = hash_pw(pw)
        if admin is not None:
            u["admin"] = admin
        if rechte is not None:
            u["rechte"] = sorted(set(rechte))
        if gesperrt is not None:
            u["gesperrt"] = gesperrt
        if not u["pw"] and not u.get("bot"):
            raise ValueError("Neuer Nutzer braucht ein Passwort.")
        save(d)


def is_bot(u: dict | None) -> bool:
    return bool(u and u.get("bot"))


KEY_RE = re.compile(r"^hmk_([a-z0-9]{6})_([A-Za-z0-9_-]{30,})$")


def key_new(name: str, art: str, label: str = "") -> str:
    """Neuen Schlüssel für einen Bot – gibt den Klartext zurück (nur dieses eine Mal)."""
    if art not in ("mcp", "freigabe"):
        raise ValueError("Art: mcp oder freigabe.")
    kid, geheim = secrets.token_hex(3), secrets.token_urlsafe(32)
    with _lock:
        d = load()
        u = d["nutzer"].get(name)
        if not u or not u.get("bot"):
            raise ValueError("Schlüssel gibt es nur für Bots.")
        u.setdefault("schluessel", []).append({"id": kid, "art": art, "hash": hashlib.sha256(geheim.encode()).hexdigest(),
                                               "name": (label or art)[:40], "erstellt": int(time.time()), "zuletzt": 0})
        save(d)
    return f"hmk_{kid}_{geheim}"


def key_drop(name: str, kid: str) -> None:
    with _lock:
        d = load()
        u = d["nutzer"].get(name) or {}
        u["schluessel"] = [k for k in u.get("schluessel", []) if k["id"] != kid]
        save(d)


_seen: dict[str, float] = {}


def key_user(tok: str, art: str) -> dict | None:
    """Bot zum Schlüssel, wenn Art passt und der Bot nicht gesperrt ist – sonst None."""
    m = KEY_RE.match(tok or "")
    if not m:
        return None
    want = hashlib.sha256(m.group(2).encode()).hexdigest()
    d = load()
    for name, u in d["nutzer"].items():
        for k in u.get("schluessel", []):
            if k["id"] == m.group(1) and k["art"] == art and hmac.compare_digest(k["hash"], want):
                if u.get("gesperrt") or not u.get("bot"):
                    return None
                now = time.time()
                if now - _seen.get(k["id"], 0) > 300:  # „zuletzt benutzt“ grob nachführen, nicht bei jedem Aufruf schreiben
                    _seen[k["id"]] = now
                    with _lock:
                        d2 = load()
                        for k2 in d2["nutzer"].get(name, {}).get("schluessel", []):
                            if k2["id"] == k["id"]:
                                k2["zuletzt"] = int(now)
                        save(d2)
                return {"name": name, **u}
    return None


def set_field(name: str, key: str, value) -> None:
    """Zusatzfeld eines Nutzers setzen (kalender_nur_haupt, slack_kanaele)."""
    if key not in ("kalender_nur_haupt", "slack_kanaele"):
        raise ValueError("Unbekanntes Feld.")
    with _lock:
        d = load()
        if name not in d["nutzer"]:
            raise ValueError(f"Nutzer {name} gibt es nicht.")
        d["nutzer"][name][key] = sorted(set(value))
        save(d)


def grant(name: str, right: str, on: bool = True) -> None:
    with _lock:
        d = load()
        u = d["nutzer"].get(name)
        if not u:
            raise ValueError(f"Nutzer {name} gibt es nicht.")
        r = set(u.get("rechte", []))
        (r.add if on else r.discard)(right)
        u["rechte"] = sorted(r)
        save(d)


def drop_right_everywhere(right: str) -> None:
    with _lock:
        d = load()
        for u in d["nutzer"].values():
            u["rechte"] = [r for r in u.get("rechte", []) if r != right]
        save(d)


def delete_user(name: str) -> None:
    with _lock:
        d = load()
        d["nutzer"].pop(name, None)
        if d.get("token_nutzer") == name:
            d.pop("token_nutzer")
        save(d)


# ── Ressourcen auf dem Pi ──────────────────────────────────────────

def accounts() -> list[str]:
    d = path("konten")
    return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json")) if os.path.isdir(d) else []


def databases() -> list[str]:
    d = path("datenbanken")
    return sorted(f[:-5] for f in os.listdir(d) if f.endswith(".json")) if os.path.isdir(d) else []


def all_rights() -> list[tuple[str, str]]:
    """Alle vergebbaren Rechte mit Beschriftung – für die Verwaltungsseite."""
    out = []
    for a in accounts():
        try:
            with open(path("konten", a + ".json"), encoding="utf-8") as f:
                kann = json.load(f).get("rechte", [])
        except (OSError, ValueError):
            kann = []
        if "mail" in kann:
            out.append((f"mail:{a}", f"✉️ Mail {a}"))
        if "kalender" in kann:
            out.append((f"kalender:{a}", f"📅 Kalender {a}"))
        if "drive" in kann:
            out.append((f"drive:{a}", f"📁 Drive/Docs/Sheets {a}"))
    out += [(f"db:{n}", f"🗄️ Datenbank {n}") for n in databases()]
    if os.path.exists(path("gitlab.json")):
        out.append(("gitlab", "🦊 GitLab"))
    if os.path.exists(path("slack.json")):
        out.append(("slack", "💬 Slack"))
    if os.path.exists(path("goatcounter.json")):
        out.append(("statistik", "📈 Besucherstatistik"))
    return out


def migrate() -> None:
    """Einmalig: altes Einzel-Passwort → Nutzer „admin“ mit allen Rechten; datenbank.json → datenbanken/heroku.json."""
    with _lock:
        old_db = path("datenbank.json")
        if os.path.exists(old_db):
            os.makedirs(path("datenbanken"), mode=0o700, exist_ok=True)
            if not os.path.exists(path("datenbanken", "heroku.json")):
                os.replace(old_db, path("datenbanken", "heroku.json"))
        if os.path.exists(path("nutzer.json")) or not os.path.exists(path("passwort")):
            return
        with open(path("passwort"), encoding="utf-8") as f:
            pw = f.read().strip()
        d = {"nutzer": {"admin": {"pw": pw, "admin": True, "gesperrt": False, "rechte": sorted(r for r, _ in all_rights())}},
             "token_nutzer": "admin"}
        save(d)
        os.replace(path("passwort"), path("passwort.alt"))
