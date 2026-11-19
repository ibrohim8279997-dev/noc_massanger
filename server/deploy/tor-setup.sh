#!/usr/bin/env bash
# Sets up the onion service for the NOC server on Debian/Ubuntu (also proot Debian in Termux). Run as root.
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
apt-get update
apt-get install -y tor
install -m 644 "$HERE/torrc.noc" /etc/tor/torrc
tor --verify-config -f /etc/tor/torrc
mkdir -p /var/log/tor && chown debian-tor:debian-tor /var/log/tor 2>/dev/null || true
# start tor (systemd if present, otherwise as the debian-tor user in the background)
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
  systemctl enable --now tor@default 2>/dev/null || systemctl enable --now tor
else
  su -s /bin/sh debian-tor -c "tor -f /etc/tor/torrc" >/dev/null 2>&1 &
fi
echo "Waiting for the onion address (up to 2 minutes)..."
for i in $(seq 1 60); do [ -s /var/lib/tor/noc_service/hostname ] && break; sleep 2; done
if [ -s /var/lib/tor/noc_service/hostname ]; then
  echo "Server address for the app:  http://$(cat /var/lib/tor/noc_service/hostname)"
  echo "BACK UP /var/lib/tor/noc_service/hs_ed25519_secret_key: whoever has it can impersonate the server."
else
  echo "No address yet. Check /var/log/tor/notices.log"
fi
