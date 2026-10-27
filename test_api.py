#!/usr/bin/env python3
"""Proditor: API-Test der Verwaltung auf dem Master (laeuft dort als root).

SPDX-License-Identifier: LGPL-3.0-or-later
Copyright (C) 2026 proditor2FA - LGPL-3.0-or-later, siehe COPYING.LESSER
"""
import hashlib, hmac, shlex, http.cookiejar, json, os, re, ssl, struct, sys, time, urllib.request

BASE = "https://localhost/admin/"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
jar = http.cookiejar.CookieJar()
op = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), urllib.request.HTTPCookieProcessor(jar))
csrf = ""
results = []

def call(action, body=None, params="", raw=False, token=None):
    url = f"{BASE}api.php?action={action}{params}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST" if body is not None else "GET")
    req.add_header("Content-Type", "application/json")
    if body is not None:
        req.add_header("X-CSRF-Token", csrf if token is None else token)
    try:
        r = op.open(req, timeout=60); code = r.status; txt = r.read().decode()
    except urllib.error.HTTPError as e:
        code = e.code; txt = e.read().decode()
    return code, (txt if raw else json.loads(txt))

def check(name, cond, info=""):
    results.append(cond); print(("OK    " if cond else "FEHLER") + f" {name} {info}")

def hotp(seed_hex, counter, digits=6):
    h = hmac.new(bytes.fromhex(seed_hex), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 10**digits).zfill(digits)

# Statische Seiten
for path, typ in [("", "text/html"), ("app.css", "text/css"), ("app.js", "javascript"), ("logo.png", "image/png")]:
    r = op.open(BASE + path); check(f"GET /admin/{path}", r.status == 200 and typ in r.headers.get("Content-Type", ""), r.headers.get("Content-Type"))
check("CSP-Header", "default-src 'self'" in op.open(BASE).headers.get("Content-Security-Policy", ""))

# Sitzung, Schutz ohne Login
code, d = call("session"); csrf = d["csrf"]
check("session", code == 200 and d["ok"] and not d["logged"], f"host={d['host']}")
check("keine Versionen vor Login", "multiotp" not in d and "php" not in d)
code, d = call("users"); check("users ohne Login -> 401", code == 401)
code, d = call("login", {"password": "x"}, token="falsch"); check("POST ohne gueltiges CSRF -> 403", code == 403)
code, d = call("login", {"password": "sicher-falsch-proditor"}); check("falsches Passwort -> 401", code == 401, d.get("error", ""))
os.remove("/tmp/motpadmin-" + hashlib.md5(b"127.0.0.1").hexdigest() + ".json") if os.path.exists("/tmp/motpadmin-" + hashlib.md5(b"127.0.0.1").hexdigest() + ".json") else None

# Nur fuer diesen Test: eigene Sitzung als angemeldet markieren (Passwort bleibt unangetastet)
sid = next(c.value for c in jar if c.name == "MOTPADMIN")
sess = f"/var/lib/php/sessions/sess_{sid}"
with open(sess, "r+") as f:  # ohne O_CREAT wegen fs.protected_regular
    s = f.read(); f.seek(0); f.write(s + "logged|b:1;"); f.truncate()

code, d = call("session")
check("Versionen nach Login", d.get("multiotp", "").startswith("5.") and d.get("php", "").startswith("8."), f"multiOTP {d.get('multiotp')} PHP {d.get('php')}")
code, d = call("users")
check("users", code == 200 and len(d["users"]) > 0, f"{len(d['users'])} Benutzer")
hotp_users = [u for u in d["users"] if u["algorithm"] == "hotp"]
check("HOTP-Benutzer mit Seriennr/Zaehler", len(hotp_users) > 0 and all("last_event" in u for u in hotp_users), f"{len(hotp_users)} HOTP")
code, d = call("tokens"); check("freie Tokens", code == 200, f"{len(d.get('tokens', []))} frei")

T = "proditor-test"
T2, T3 = "proditor-test-totp", "proditor-test-ohne"
STICK = "proditortest-stick01"
SEED = "3132333435363738393031323334353637383930"

def php(code):
    boot = ('error_reporting(0);chdir("/usr/local/bin/multiotp");require "multiotp.class.php";'
            '$m=new Multiotp("DefaultCliEncryptionKey",false,"","/etc/multiotp/config");$m->SetHashSalt(_MULTIOTP_DEFAULT_HASH_SALT_);'
            '$m->SetConfigFolder("/etc/multiotp/config/");$m->SetUsersFolder("/etc/multiotp/users/");$m->SetTokensFolder("/etc/multiotp/tokens/");'
            '$m->SetLinuxFileMode("0666");$m->ReadConfigData();')
    return os.popen("sudo -u www-data php -r " + shlex.quote(boot + code)).read().strip()

for u in (T, T2, T3):
    call("delete", {"user": u, "confirm": u})
php(f'$m->DeleteToken("{STICK}");')
php(f'$m->CreateToken("{STICK}","hotp","{SEED}",8,0);')
code, d = call("tokens"); check("Test-Stick in freien Sticks", STICK in d.get("tokens", []))

code, d = call("create", {"user": T, "kind": "hotp"}); check("Art 'hotp' abgelehnt", code == 400, d.get("error", ""))
code, d = call("create", {"user": T, "kind": "stick", "serial": "gibt-es-nicht-9999"}); check("unbekannter Stick abgelehnt", code == 400, d.get("error", ""))
code, d = call("create", {"user": T, "kind": "stick", "serial": STICK})  # nur Pflichtangaben
check("Benutzer mit Proditor-Stick nur mit Name + Stick", code == 200 and d["user"]["algorithm"] == "hotp" and d["user"]["serial"] == STICK and d["user"]["digits"] == 8, d.get("error", ""))
code, d = call("create", {"user": T2, "kind": "stick", "serial": STICK}); check("vergebener Stick -> 409", code == 409, d.get("error", ""))
code, d = call("tokens"); check("Test-Stick nicht mehr frei", STICK not in d.get("tokens", []))
code, d = call("create", {"user": T, "kind": "totp"}); check("create doppelt -> 409", code == 409)
code, d = call("create", {"user": T2, "kind": "totp", "pin": "4711"}); check("Benutzer mit QR-Code (TOTP) und PIN", code == 200 and d["user"]["algorithm"] == "totp", d.get("error", ""))
check("PIN vorhanden -> Prefix-PIN aktiv", php(f'$m->ReadUserData("{T2}",false,true);echo $m->IsUserPrefixPin()?"1":"0";') == "1")
check("ohne PIN -> kein Prefix-PIN", php(f'$m->ReadUserData("{T}",false,true);echo $m->IsUserPrefixPin()?"1":"0";') == "0")
code, txt = call("qr", params=f"&user={T2}", raw=True); check("QR-Seite TOTP", code == 200 and "<img" in txt.lower())
code, d = call("create", {"user": T3, "kind": "without2fa", "description": "", "email": ""}); check("Benutzer Without2FA nur mit Name", code == 200 and d["user"]["algorithm"] == "without2fa", d.get("error", ""))
seed = SEED

def hotp(seed_hex, counter, digits=8):
    h = hmac.new(bytes.fromhex(seed_hex), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 15
    return str((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 10**digits).zfill(digits)

code, d = call("counter", {"user": T, "next": 1000})
check("Zaehler auf 1000 setzen", code == 200 and d["user"]["last_event"] == 999)
code, d = call("check", {"user": T, "otp": hotp(seed, 999)})
check("Code zu Zaehler 999 (alt) abgelehnt", code == 200 and not d["valid"], d.get("message", ""))
code, d = call("check", {"user": T, "otp": hotp(seed, 1000)})
check("Code zu Zaehler 1000 gueltig", code == 200 and d["valid"], d.get("message", ""))
check("Zaehler danach 1001", d["user"]["last_event"] + 1 == 1001)
code, d = call("counter", {"user": T, "next": 0}); check("Zaehler 0 abgelehnt", code == 400)
code, d = call("counter", {"user": T, "next": "abc"}); check("Zaehler Text abgelehnt", code == 400)
code, d = call("resync", {"user": T, "otp1": hotp(seed, 1010), "otp2": hotp(seed, 1011)})
check("Resync im Fenster", code == 200 and d["user"]["last_event"] >= 1010, f"last_event={d.get('user', {}).get('last_event')} {d.get('error', '')}")
code, d = call("resync", {"user": T, "otp1": hotp(seed, 5000), "otp2": hotp(seed, 5001)})
check("Resync weit entfernt (5000/5001)", code == 200 and d["user"]["last_event"] == 5001, f"last_event={d.get('user', {}).get('last_event')} {d.get('error', '')}")
code, d = call("resync", {"user": T, "otp1": "123456", "otp2": "654321"})
check("Resync mit falschen Codes abgelehnt", code == 400, d.get("error", ""))
code, d = call("lock", {"user": T}); check("sperren", code == 200 and d["user"]["locked"])
code, d = call("unlock", {"user": T}); check("entsperren", code == 200 and not d["user"]["locked"])
code, d = call("counter", {"user": "gibt-es-nicht-xyz", "next": 5}); check("unbekannter Benutzer -> 404", code == 404)
code, d = call("delete", {"user": T, "confirm": "falsch"}); check("loeschen ohne Bestaetigung abgelehnt", code == 400)
code, d = call("delete", {"user": T, "confirm": T}); check("loeschen", code == 200)
for u in (T2, T3):
    code, d = call("delete", {"user": u, "confirm": u}); check(f"loeschen {u}", code == 200)
php(f'$m->DeleteToken("{STICK}");')
check("Test-Stick entfernt", not os.path.exists(f"/etc/multiotp/tokens/{STICK}.db"))
code, d = call("users"); check("Testbenutzer weg", not any(u["user"].startswith("proditor-test") for u in d["users"]))
code, d = call("logout", {}); code, d = call("users"); check("nach Logout -> 401", code == 401)

log = os.popen("php /usr/local/bin/multiotp/multiotp.php -showlog 2>/dev/null | grep 'Verwaltung (Proditor' | tail -3").read()
check("Audit-Eintraege im multiOTP-Log", "Zaehler" in log or "geloescht" in log)
print(log.strip())
print(f"\n{sum(results)}/{len(results)} Tests bestanden")
sys.exit(0 if all(results) else 1)
