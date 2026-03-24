#!/bin/bash
# ─────────────────────────────────────────────
#  SSRF Prober - Installer for Linux / Kali
# ─────────────────────────────────────────────

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════╗"
echo "║        SSRF Prober — Installer           ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${NC}"

# Check Python 3.10+
PYTHON=$(which python3 2>/dev/null || which python 2>/dev/null)
if [ -z "$PYTHON" ]; then
    echo -e "${RED}[✗] Python 3 not found. Install it first.${NC}"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "[*] Python version: ${PY_VERSION}"

# Install dependencies
echo -e "[*] Installing dependencies..."
$PYTHON -m pip install --quiet --break-system-packages -r requirements.txt 2>/dev/null \
    || $PYTHON -m pip install --quiet -r requirements.txt

# Make executable
chmod +x ssrf_prober.py

# Optional: create symlink for global use
if [ "$EUID" -eq 0 ]; then
    ln -sf "$(pwd)/ssrf_prober.py" /usr/local/bin/ssrf-prober
    echo -e "${GREEN}[✓] Installed globally as 'ssrf-prober'${NC}"
else
    echo -e "[!] Run as root to install globally (optional)."
    echo -e "    sudo bash install.sh"
fi

echo -e ""
echo -e "${GREEN}[✓] Installation complete!${NC}"
echo -e ""
echo -e "Usage:"
echo -e "  python3 ssrf_prober.py -u 'https://target.com/fetch?url=FUZZ'"
echo -e "  python3 ssrf_prober.py --help"
echo -e ""
