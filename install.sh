#!/bin/bash
# SPDX-License-Identifier: LGPL-3.0-or-later
# Copyright (C) 2026 proditor2FA - LGPL-3.0-or-later, siehe COPYING.LESSER
#
# Installiert Proditor-admin auf einem multiOTP-Server (nginx + php-fpm).
# Aufruf als root im Verzeichnis des Repos:  ./install.sh
# Mehrfach ausfuehrbar: Dateien werden aktualisiert, nginx-Bloecke nur einmal eingefuegt.

set -euo pipefail

TARGET=/usr/local/bin/multiotp-admin
SITE=/etc/nginx/sites-available/multiotp
FILES=(index.html app.css app.js api.php logo.png logo-icon.png favicon.png)
MARK="# Proditor: moderne Verwaltung unter /admin/"

cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "Bitte als root ausfuehren."; exit 1; }
[ -f /usr/local/bin/multiotp/multiotp.class.php ] || { echo "multiOTP nicht gefunden (/usr/local/bin/multiotp)."; exit 1; }
[ -f "$SITE" ] || { echo "nginx-Site $SITE nicht gefunden."; exit 1; }

SOCK=$(ls /run/php/php*-fpm.sock 2>/dev/null | sort -V | tail -1)
[ -n "$SOCK" ] || { echo "Kein php-fpm-Socket unter /run/php gefunden."; exit 1; }

install -d -o root -g www-data -m 750 "$TARGET"
for f in "${FILES[@]}"; do
  install -o root -g www-data -m 640 "$f" "$TARGET/$f"
done
echo "Dateien nach $TARGET kopiert."

# credusers-Ordner, den multiOTP 5.10 erwartet
install -d -o www-data -g www-data -m 777 /etc/multiotp/credusers

if grep -qF "$MARK" "$SITE"; then
  echo "nginx-Bloecke sind schon vorhanden."
else
  cp -p "$SITE" "$SITE.vor-proditor-admin"
  python3 - "$SITE" "$SOCK" docs/nginx-multiotp.conf <<'EOF'
import re, sys
site, sock, snippet = sys.argv[1:4]
s = open(site).read()
block = open(snippet).read()
block = re.sub(r"unix:/var/run/php/php[0-9.]+-fpm\.sock", "unix:" + sock, block)
anchor = "    location ~ \\.php$ {"
if s.count(anchor) != 1:
    sys.exit("Ankerstelle 'location ~ \\.php$' nicht eindeutig gefunden, bitte docs/nginx-multiotp.conf von Hand einfuegen.")
open(site, "w").write(s.replace(anchor, block.rstrip("\n") + "\n\n" + anchor))
EOF
  echo "nginx-Bloecke eingefuegt (Sicherung: $SITE.vor-proditor-admin)."
fi

nginx -t
systemctl reload nginx
echo "Fertig: https://<server>/admin/"
