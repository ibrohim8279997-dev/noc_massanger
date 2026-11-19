#!/usr/bin/env bash
# Looks at THIS machine and reports anything that breaks the server rules. Exit code 1 if something does.
# For tests the inputs can be replaced:  NOC_AUDIT_SS=file  NOC_AUDIT_PS=file
bad=0
say() { echo "$1"; bad=1; }
ss_out=$( [ -n "${NOC_AUDIT_SS:-}" ] && cat "$NOC_AUDIT_SS" || ss -ltnuH 2>/dev/null )
ps_out=$( [ -n "${NOC_AUDIT_PS:-}" ] && cat "$NOC_AUDIT_PS" || ps -eo comm= 2>/dev/null )
# 1. nothing may listen on anything but loopback
while read -r proto state rq sq local peer; do
  [ -z "$local" ] && continue
  case "$local" in 127.0.0.1:*|\[::1\]:*|::1:*) ;; *) say "LISTENING ON NON-LOOPBACK: $proto $local" ;; esac
done <<< "$ss_out"
# 2. no remote administration or VPN mesh software running
for p in sshd tailscaled zerotier-one openvpn wireguard telnetd; do
  echo "$ps_out" | grep -qx "$p" && say "FORBIDDEN PROCESS RUNNING: $p"
done
# 3. the database directory belongs to the service user and is private
if [ -d /var/lib/noc ]; then
  [ "$(stat -c %a /var/lib/noc)" = "700" ] || say "/var/lib/noc is not mode 700"
  [ "$(stat -c %U /var/lib/noc)" = "noc" ] || say "/var/lib/noc is not owned by noc"
fi
[ $bad = 0 ] && echo "AUDIT OK"
exit $bad
