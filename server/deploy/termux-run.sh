#!/data/data/com.termux/files/usr/bin/bash
# Starts the server in a tmux session that survives closing Termux's window.
# First run: creates a DB key, shows it ONCE (write it down, store it away from this phone), starts the server.
set -e
cd "$(dirname "$0")/.."
export NOC_DB_PATH="$HOME/noc-data/noc.db"
termux-wake-lock 2>/dev/null || true          # keeps the CPU awake while the server runs
if tmux has-session -t noc 2>/dev/null; then
  echo "Server session already running. Attaching (detach with Ctrl-b then d)."
  exec tmux attach -t noc
fi
if [ ! -f "$NOC_DB_PATH" ]; then
  echo "No database yet. New DB key (write it down NOW, it is not stored anywhere):"
  python -m app.cli init-key
  echo
fi
# the key is typed into the server's own prompt and never written to disk
exec tmux new-session -s noc "python -m app.cli serve --host ${NOC_HOST:-0.0.0.0} --port 8443; echo 'server stopped, press Enter'; read"
