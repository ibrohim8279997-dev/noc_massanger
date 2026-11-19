#!/usr/bin/env bash
# One-time setup on Debian/Ubuntu (also proot-distro Debian inside Termux, arm64). Run as root or with sudo.
set -e
cd "$(dirname "$0")/.."
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
$SUDO apt-get update
$SUDO apt-get install -y python3 python3-venv python3-pip tmux
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
# sqlcipher3-binary has no arm64 build; sqlcipher3-wheels does (and is tested with this server)
pip install fastapi==0.165.0 uvicorn==0.54.0 pynacl==1.6.2 sqlcipher3-wheels
python - <<'PY'
import sqlcipher3 as s
c = s.connect(":memory:"); c.execute("pragma key='k'")
print("SQLCipher OK:", c.execute("pragma cipher_version").fetchone()[0])
PY
mkdir -p "$HOME/noc-data"
echo "Setup finished. Next: bash deploy/linux-run.sh"
