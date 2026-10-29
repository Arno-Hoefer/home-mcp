"""Drive-Werkzeuge mit gemockter Google-API: Ordner, Upload, Ordner-Paket, Freigabe mit Ablage, Zurücknehmen.

Aufruf: python3 -m unittest discover -s tests   (im Repo-Ordner)
"""
import base64
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import urllib.request

TMP = tempfile.mkdtemp(prefix="home-mcp-test-")
os.environ["HOME_MCP_HOME"] = TMP
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import home_mcp as h  # noqa: E402
import freigaben  # noqa: E402
import nutzer  # noqa: E402

KONTO = "a@example.org"


class Antwort(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Google:
    """Fängt urlopen ab, merkt sich die Anfragen und antwortet wie die Drive-/Sheets-API."""

    def __init__(self):
        self.anfragen = []
        self.n = 0

    def __call__(self, req, timeout=None):
        url, meth, data = req.full_url, req.get_method(), req.data or b""
        self.anfragen.append((meth, url, data, dict(req.header_items())))
        self.n += 1
        fid = f"id{self.n:08d}xx"
        if "/upload/drive/v3/files" in url:
            meta = json.loads(data.split(b"\r\n\r\n", 1)[1].split(b"\r\n--", 1)[0])
            return Antwort(json.dumps({"id": fid, "name": meta["name"], "webViewLink": f"https://drive.example/{fid}"}).encode())
        if url.startswith(h.DRIVE + "/files") and meth == "POST":
            return Antwort(json.dumps({"id": fid, "name": json.loads(data)["name"], "webViewLink": f"https://drive.example/{fid}"}).encode())
        if meth == "PATCH" or "/values/" in url:
            return Antwort(b"{}")
        raise AssertionError(f"unerwartete Anfrage {meth} {url}")


class DriveTest(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(TMP, ignore_errors=True)
        os.makedirs(os.path.join(TMP, "konten"))
        with open(os.path.join(TMP, "konten", KONTO + ".json"), "w") as f:
            json.dump({"rechte": ["drive"], "refresh_token": "x"}, f)
        nutzer.save({"nutzer": {"mensch": {"pw": "", "rechte": [f"drive:{KONTO}"]},
                                "botx": {"pw": "", "bot": True, "schluessel": [], "rechte": [f"drive:{KONTO}"]}}})
        self.g = Google()
        self._alt = (urllib.request.urlopen, h.access_token)
        urllib.request.urlopen = self.g
        h.access_token = lambda addr: "tok"

    def tearDown(self):
        urllib.request.urlopen, h.access_token = self._alt
        h._cur.user = None

    def als(self, name):
        h._cur.user = nutzer.get(name)

    def rpc(self, tool, args):
        r = h.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}})
        return r["result"]["content"][0]["text"], r["result"]["isError"]

    def test_werkzeuge_sichtbar(self):
        self.als("botx")
        namen = {t["name"]: t for t in h.handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
        for t in ("drive_ordner_anlegen", "drive_hochladen", "drive_ordner_paket"):
            self.assertIn(t, namen)
            self.assertIn("BRAUCHT FREIGABE", namen[t]["description"])
        self.assertIn("ordner", namen["doc_anlegen"]["inputSchema"]["properties"])
        self.assertIn("ordner", namen["sheet_anlegen"]["inputSchema"]["properties"])

    def test_ordner_und_upload_direkt(self):
        self.als("mensch")
        t, err = self.rpc("drive_ordner_anlegen", {"name": "Gewerbeplan"})
        self.assertFalse(err, t)
        self.assertIn("(id id00000001xx)", t)
        meta = json.loads(self.g.anfragen[0][2])
        self.assertEqual(meta["mimeType"], h.ORDNER_MIME)
        self.assertNotIn("parents", meta)
        pdf = b"%PDF-1.4 hallo\x00\xff"
        t, err = self.rpc("drive_hochladen", {"name": "Plan.pdf", "base64": base64.b64encode(pdf).decode(), "ordner": "id00000001xx"})
        self.assertFalse(err, t)
        meth, url, data, kopf = self.g.anfragen[-1]
        self.assertIn("uploadType=multipart", url)
        self.assertIn(pdf, data)  # Bytes unverändert im Multipart
        self.assertIn(b"Content-Type: application/pdf", data)
        self.assertIn(b'"parents": ["id00000001xx"]', data)

    def test_upload_grenzen(self):
        self.als("mensch")
        alt = h.DATEI_MAX
        h.DATEI_MAX = 10
        try:
            t, err = self.rpc("drive_hochladen", {"name": "gross.bin", "base64": base64.b64encode(b"x" * 11).decode()})
        finally:
            h.DATEI_MAX = alt
        self.assertTrue(err)
        self.assertIn("zu groß", t)
        t, err = self.rpc("drive_hochladen", {"name": "x.txt"})
        self.assertTrue(err)
        t, err = self.rpc("drive_hochladen", {"name": "x.bin", "_ablage": "0" * 64})
        self.assertTrue(err)  # Ablage nur beim Ausführen einer Freigabe

    def test_als_google_und_doc_sheet_im_ordner(self):
        self.als("mensch")
        t, err = self.rpc("drive_hochladen", {"name": "Finanzen.xlsx", "inhalt": "x", "als_google": True})
        self.assertFalse(err, t)
        self.assertIn(b"application/vnd.google-apps.spreadsheet", self.g.anfragen[-1][2])
        t, err = self.rpc("doc_anlegen", {"titel": "Notiz", "text": "# Hallo", "ordner": "https://drive.google.com/drive/folders/abcdefghijkl"})
        self.assertFalse(err, t)
        self.assertIn(b'"parents": ["abcdefghijkl"]', self.g.anfragen[-1][2])
        t, err = self.rpc("sheet_anlegen", {"titel": "Zahlen", "zeilen": [["a", 1]], "ordner": "abcdefghijkl"})
        self.assertFalse(err, t)
        self.assertEqual(json.loads(self.g.anfragen[-2][2])["parents"], ["abcdefghijkl"])
        self.assertIn("/values/A1", self.g.anfragen[-1][1])

    def paket(self):
        return {"name": "Gewerbeplan Café", "dateien": [
            {"name": "Übersicht", "art": "doc", "text": "# Übersicht\n- a"},
            {"name": "Finanzplan", "art": "sheet", "zeilen": [["Monat", "Umsatz"], ["Jan", 100]], "unterordner": "Finanzen"},
            {"name": "Businessplan.pdf", "art": "datei", "base64": base64.b64encode(b"%PDF-1.4 x" * 100).decode(), "unterordner": "Original/Unterlagen"},
            {"name": "../../böse", "art": "datei", "inhalt": "x", "unterordner": "../.."},
        ]}

    def test_paket_als_bot_eine_freigabe(self):
        self.als("botx")
        t, err = self.rpc("drive_ordner_paket", self.paket())
        self.assertFalse(err, t)
        self.assertIn("Wartet auf Freigabe", t)
        self.assertEqual(self.g.anfragen, [])  # noch nichts bei Google
        (f,) = freigaben.liste("botx")
        self.assertIn("mit 4 Dateien", f["text"])
        self.assertIn("📊 Sheet „Finanzen/Finanzplan“ (2 Zeilen)", f["text"])
        self.assertIn("📎 Original/Unterlagen/Businessplan.pdf (1 KB)", f["text"])
        roh = json.dumps(f["args"])
        self.assertNotIn("base64", roh)  # Bytes liegen in der Ablage, nicht in freigaben.json
        ablage = os.listdir(os.path.join(TMP, "ablage"))
        self.assertEqual(len(ablage), 2)
        # Ausführen nach dem Ja
        h._cur.user = None
        f = freigaben.entscheiden(f["id"], True, "app", h.freigabe_ausfuehren)
        self.assertEqual(f["status"], "ausgefuehrt", f.get("ergebnis"))
        self.assertIn("4 von 4 Dateien angelegt", f["ergebnis"])
        ordner = [json.loads(d) for m, u, d, _ in self.g.anfragen if u.startswith(h.DRIVE + "/files") and m == "POST"
                  and json.loads(d).get("mimeType") == h.ORDNER_MIME]
        self.assertEqual([o["name"] for o in ordner], ["Gewerbeplan Café", "Finanzen", "Original", "Unterlagen"])  # „..“ fällt weg
        hoch = [d for m, u, d, _ in self.g.anfragen if "/upload/" in u]
        self.assertTrue(any(b"%PDF-1.4 x%PDF" in d for d in hoch))
        self.assertTrue(any(b'"name": ".._.._b\\u00f6se"' in d or b'"name": "..' in d for d in hoch))  # kein / im Namen
        # Ablage nach dem Ausführen aufgeräumt (Schonfrist abgelaufen gedacht)
        for n in os.listdir(os.path.join(TMP, "ablage")):
            os.utime(os.path.join(TMP, "ablage", n), (0, 0))
        h.ablage_aufraeumen()
        self.assertEqual(os.listdir(os.path.join(TMP, "ablage")), [])

    def test_paket_zuruecknehmen(self):
        self.als("botx")
        self.rpc("drive_ordner_paket", {"name": "X", "dateien": [{"name": "a", "art": "doc", "text": "t"}]})
        (f,) = freigaben.liste("botx")
        h._cur.user = None
        freigaben.entscheiden(f["id"], True, "app", h.freigabe_ausfuehren)
        f = freigaben.zuruecknehmen(f["id"], "app", h.freigabe_zuruecknehmen)
        self.assertEqual(f["status"], "zurueckgenommen")
        meth, url, data, _ = self.g.anfragen[-1]
        self.assertEqual(meth, "PATCH")
        self.assertTrue(url.startswith(h.DRIVE + "/files/id00000001xx"))
        self.assertEqual(json.loads(data), {"trashed": True})

    def test_paket_pruefung(self):
        self.als("botx")
        for args in ({"name": "X", "dateien": []}, {"name": "X", "dateien": [{"name": "a", "art": "pdf"}]},
                     {"name": "", "dateien": [{"name": "a", "art": "doc"}]},
                     {"name": "X", "dateien": [{"name": "a", "art": "datei"}]},
                     {"name": "X", "dateien": [{"name": "a", "art": "doc", "_ablage": "0" * 64}]}):
            t, err = self.rpc("drive_ordner_paket", args)
            self.assertTrue(err, (args, t))
        self.assertEqual(freigaben.liste("botx"), [])
        alt = h.PAKET_MAX
        h.PAKET_MAX = 50
        try:
            t, err = self.rpc("drive_ordner_paket", {"name": "X", "dateien": [{"name": "a.bin", "art": "datei", "inhalt": "x" * 30},
                                                                             {"name": "b.bin", "art": "datei", "inhalt": "y" * 30}]})
        finally:
            h.PAKET_MAX = alt
        self.assertTrue(err)
        self.assertIn("Zusammen zu groß", t)

    def test_fehler_einzelner_dateien(self):
        self.als("mensch")
        t, err = self.rpc("drive_ordner_paket", {"name": "X", "dateien": [{"name": "a", "art": "doc", "text": "t"},
                                                                         {"name": "b.bin", "art": "datei"}]})
        self.assertFalse(err, t)
        self.assertIn("1 von 2 Dateien angelegt", t)
        self.assertIn("✗ b.bin", t)


if __name__ == "__main__":
    unittest.main()
