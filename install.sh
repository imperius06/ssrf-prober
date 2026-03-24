#!/bin/bash
set -e

CYAN='\033[0;36m'; GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║         SSRF Prober v2.0 — Installer             ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
[ -z "$PYTHON" ] && { echo -e "${RED}[✗] Python 3 not found.${NC}"; exit 1; }

echo -e "[*] Python: $($PYTHON --version)"
echo -e "[*] Installing dependencies..."

$PYTHON -m pip install --quiet --break-system-packages -r requirements.txt 2>/dev/null \
    || $PYTHON -m pip install --quiet -r requirements.txt

chmod +x ssrf_prober.py

if [ "$EUID" -eq 0 ]; then
    ln -sf "$(pwd)/ssrf_prober.py" /usr/local/bin/ssrf-prober
    echo -e "${GREEN}[✓] Installed globally as 'ssrf-prober'${NC}"
fi

echo -e "\n${GREEN}[✓] Done! Run with:${NC}"
echo -e "    python3 ssrf_prober.py\n"
