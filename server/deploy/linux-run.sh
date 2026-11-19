#!/usr/bin/env bash
# Starts the server inside a tmux session that keeps running after you close the terminal window.
set -e
cd "$(dirname "$0")/.."
export NOC_DB_PATH="$HOME/noc-data/noc.db"
if tmux has-session -t noc 2>/dev/null; then
  echo "Server session already running. Attaching (detach with Ctrl-b then d)."
  exec tmux attach -t noc
fi
if [ ! -f "$NOC_DB_PATH" ]; then
  echo "No database yet. New DB key (write it down NOW, it is not stored anywhere):"
  .venv/bin/python -m app.cli init-key
  echo
fi
# the key is typed into the server's own prompt and never written to disk
exec tmux new-session -s noc "NOC_DB_PATH='$NOC_DB_PATH' .venv/bin/python -m app.cli serve --host 0.0.0.0 --port 8443; echo 'server stopped, press Enter'; read"
