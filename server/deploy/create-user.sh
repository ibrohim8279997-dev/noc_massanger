#!/usr/bin/env bash
# Creates the unprivileged account the server runs as. It owns ONLY the database directory.
set -e
id noc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin noc
install -d -m 700 -o noc -g noc /var/lib/noc
echo "user 'noc' ready; data directory /var/lib/noc (mode 700)"
echo "start the server as that user:  NOC_RUN_AS=noc bash server/deploy/linux-run.sh"
