"""
Freigaben: Schreibaktionen von Bots warten, bis der Mensch sie in der App (oder auf der Verwaltungsseite) bestätigt.

<HOME>/freigaben.json:
  {"F-ab12cd": {"user": "nookbot", "tool": "termin_anlegen", "args": {...}, "text": "Termin „…“ am …",
                "status": "offen"|"ausgefuehrt"|"abgelehnt"|"fehler"|"abgelaufen"|"zurueckgenommen", "erstellt": ts,
                "entschieden": ts, "von": "app"|"verwaltung:admin", "ergebnis": "…"}}

Ausgeführt wird erst nach dem Ja – mit genau den gespeicherten Argumenten und den Rechten, die der Bot DANN hat.
Offene Freigaben verfallen nach 24 Stunden. Erledigte werden nach 30 Tagen aufgeräumt.
"""
import json
import os
import secrets
import threading
import time

import nutzer

TTL = 24 * 3600
KEEP = 30 * 86400
_lock = threading.RLock()


def _path() -> str:
    return nutzer.path("freigaben.json")


def _load() -> dict:
    try:
        with open(_path(), encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError):
        d = {}
    now = time.time()
    for v in d.values():
        if v["status"] == "offen" and now - v["erstellt"] > TTL:
            v.update(status="abgelaufen", entschieden=now)
    return {k: v for k, v in d.items() if v["status"] == "offen" or now - v.get("entschieden", now) < KEEP}


def _save(d: dict) -> None:
    nutzer._write_json(_path(), d)


def neu(user: str, tool: str, args: dict, text: str) -> str:
    with _lock:
        d = _load()
        if sum(1 for v in d.values() if v["user"] == user and v["status"] == "offen") >= 20:
            raise ValueError("Schon 20 offene Freigaben – erst entscheiden lassen.")
        fid = "F-" + secrets.token_hex(3)
        d[fid] = {"user": user, "tool": tool, "args": args, "text": text, "status": "offen", "erstellt": time.time()}
        _save(d)
    return fid


def get(fid: str) -> dict | None:
    with _lock:
        v = _load().get(fid)
    return {"id": fid, **v} if v else None


def liste(user: str | None = None, nur_offen: bool = False, n: int = 50) -> list[dict]:
    with _lock:
        d = _load()
    out = [{"id": k, **v} for k, v in d.items() if (user is None or v["user"] == user) and (not nur_offen or v["status"] == "offen")]
    out.sort(key=lambda v: (v["status"] != "offen", -v["erstellt"]))
    return out[:n]


def zuruecknehmen(fid: str, von: str, ruecknahme) -> dict:
    """Eine ausgeführte Freigabe rückgängig machen. ruecknahme(freigabe) -> Text (wirft, wenn es nicht geht)."""
    with _lock:
        d = _load()
        v = d.get(fid)
        if not v:
            raise KeyError("Freigabe gibt es nicht (mehr).")
        if v["status"] != "ausgefuehrt":
            raise ValueError(f"Nur Ausgeführtes lässt sich zurücknehmen (Status: {v['status']}).")
    res = ruecknahme({"id": fid, **v})
    with _lock:
        d = _load()
        d[fid].update(status="zurueckgenommen", zurueck=time.time(), zurueck_von=von, ergebnis=(d[fid].get("ergebnis", "") + "\n↩ " + res)[:2400])
        _save(d)
        return {"id": fid, **d[fid]}


def entscheiden(fid: str, ja: bool, von: str, ausfuehren) -> dict:
    """ausfuehren(freigabe) -> Ergebnistext (wirft bei Fehler). Gibt die aktualisierte Freigabe zurück."""
    with _lock:
        d = _load()
        v = d.get(fid)
        if not v:
            raise KeyError("Freigabe gibt es nicht (mehr).")
        if v["status"] != "offen":
            raise ValueError(f"Schon entschieden: {v['status']}.")
        v.update(status="laeuft" if ja else "abgelehnt", entschieden=time.time(), von=von)
        _save(d)
    if ja:  # außerhalb der Sperre ausführen (Google kann dauern); „laeuft“ verhindert doppeltes Ja
        try:
            res, st = ausfuehren({"id": fid, **v}), "ausgefuehrt"
        except Exception as ex:  # noqa: BLE001
            res, st = f"Fehler: {ex}", "fehler"
        with _lock:
            d = _load()
            if fid in d:
                d[fid].update(status=st, ergebnis=str(res)[:2000])
                _save(d)
                v = d[fid]
    return {"id": fid, **v}
