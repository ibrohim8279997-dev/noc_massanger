#!/usr/bin/env bash
# Starts the server inside a tmux session that keeps running after you close the terminal window.
set -e
cd "$(dirname "$0")/.."
export NOC_DB_PATH="$HOME/noc-data/noc.db"
# behind Tor: start with NOC_HOST=127.0.0.1 so that the onion service is the only way in
export NOC_HOST="${NOC_HOST:-0.0.0.0}"
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
RUNAS=""
if [ -n "${NOC_RUN_AS:-}" ]; then   # run as the unprivileged service user: it can touch only /var/lib/noc
  export NOC_DB_PATH="/var/lib/noc/noc.db"
  RUNAS="setpriv --reuid=$NOC_RUN_AS --regid=$NOC_RUN_AS --clear-groups --no-new-privs"
fi
exec tmux new-session -s noc "$RUNAS env NOC_HOST='$NOC_HOST' NOC_DB_PATH='$NOC_DB_PATH' NOC_DB_KEY_FILE='${NOC_DB_KEY_FILE:-}' .venv/bin/python -m app.cli serve --host ${NOC_HOST:-0.0.0.0} --port 8443; echo 'server stopped, press Enter'; read"
