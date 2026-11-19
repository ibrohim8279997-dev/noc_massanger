#!/data/data/com.termux/files/usr/bin/bash
# One-time setup of the NOC server in Termux. Run from anywhere: bash server/deploy/termux-setup.sh
set -e
cd "$(dirname "$0")/.."
pkg update -y
pkg install -y python tmux git openssl libffi libsodium rust binutils clang make
pip install --upgrade pip
export SODIUM_INSTALL=system
pip install fastapi==0.165.0 "uvicorn==0.54.0" pynacl==1.6.2
echo "--- SQLCipher binding"
if pip install sqlcipher3-binary==0.6.0; then
  echo "sqlcipher3-binary installed"
else
  echo "binary wheel unavailable on Android, trying to build from source"
  pkg install -y sqlcipher || true
  pip install sqlcipher3 || { echo "SQLCIPHER FAILED: send this output to the developer"; exit 1; }
fi
python - <<'PY'
import sqlcipher3 as s
c = s.connect(":memory:"); c.execute("pragma key='k'")
print("SQLCipher OK:", c.execute("pragma cipher_version").fetchone()[0])
PY
mkdir -p "$HOME/noc-data"
echo "Setup finished. Next: bash server/deploy/termux-run.sh"
