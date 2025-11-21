#!/bin/bash
set -euo pipefail

# === KONFIGURATION ===
# RAW-URL zum Python-Script im GitHub-Repository (bitte Benutzername anpassen)
RAW_URL="https://raw.githubusercontent.com/st3ffx/domain-checker/main/domain_check_de.py"
TARGET="/usr/local/bin/domaincheck"

echo "== Domaincheck Installer =="

# 1. Root-Rechte prüfen
if [ "$EUID" -ne 0 ]; then
  echo "Bitte als root ausführen (z. B. mit sudo)."
  exit 1
fi

# 2. Abhängigkeiten prüfen und ggf. installieren
echo "Prüfe benötigte Pakete..."

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 nicht gefunden."
  if command -v dnf >/dev/null 2>&1; then
    echo "Installiere python3 über dnf..."
    dnf install -y python3
  else
    echo "Bitte python3 manuell installieren."
  fi
else
  echo "python3 ist vorhanden."
fi

if ! command -v pip3 >/dev/null 2>&1; then
  echo "pip3 nicht gefunden."
  if command -v dnf >/dev/null 2>&1; then
    echo "Installiere python3-pip über dnf..."
    dnf install -y python3-pip
  else
    echo "Bitte pip3 manuell installieren."
  fi
else
  echo "pip3 ist vorhanden."
fi

if ! command -v whois >/dev/null 2>&1; then
  echo "whois nicht gefunden."
  if command -v dnf >/dev/null 2>&1; then
    echo "Installiere whois über dnf..."
    dnf install -y whois
  else
    echo "Bitte whois manuell installieren."
  fi
else
  echo "whois ist vorhanden."
fi

# Python-Modul installieren
echo "Installiere Python-Modul 'dnspython' (falls noch nicht vorhanden)..."
pip3 install --upgrade dnspython >/dev/null 2>&1 || true

# 3. Script herunterladen
echo "Lade domain_check_de.py herunter..."

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$RAW_URL" -o "$TARGET"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$RAW_URL" -O "$TARGET"
else
  echo "Weder curl noch wget gefunden. Bitte eines davon installieren."
  exit 1
fi

chmod +x "$TARGET"

echo
echo "Installation erfolgreich abgeschlossen!"
echo "Das Tool kann nun wie folgt verwendet werden:"
echo "    domaincheck example.com"
echo
