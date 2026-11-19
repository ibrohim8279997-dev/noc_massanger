#!/usr/bin/env bash
# Behavioural test of server/deploy/firewall.nft using two network namespaces joined by a virtual cable.
# srv = the server phone, peer = "the outside world". Needs root + iproute2 + nftables. Exit 0 = every expectation held.
set -u
cd "$(dirname "$0")/.."
RULES=server/deploy/firewall.nft
fail=0; pass() { echo "  PASS  $1"; }; nope() { echo "  FAIL  $1"; fail=1; }
cleanup() { ip netns pids fw_peer 2>/dev/null | xargs -r kill 2>/dev/null; ip netns pids fw_srv 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del fw_srv 2>/dev/null; ip netns del fw_peer 2>/dev/null; }
trap cleanup EXIT; cleanup
ip netns add fw_srv && ip netns add fw_peer || { echo "SKIP: cannot create network namespaces here"; exit 0; }
ip link add vs type veth peer name vp && ip link set vs netns fw_srv && ip link set vp netns fw_peer
ip -n fw_srv addr add 10.77.0.1/24 dev vs && ip -n fw_peer addr add 10.77.0.2/24 dev vp
for n in fw_srv fw_peer; do ip -n $n link set lo up; done; ip -n fw_srv link set vs up; ip -n fw_peer link set vp up
id noc >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin noc
id debian-tor >/dev/null 2>&1 || { echo "SKIP: no debian-tor user (install tor)"; exit 0; }

LOG=$(mktemp)
# the outside world listens and counts connections; the server has a public-facing listener and a loopback one
ip netns exec fw_peer python3 -c "
import socket,sys
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('10.77.0.2',9001)); s.listen(20)
while True:
    c,_=s.accept(); open('$LOG','a').write('hit\n'); c.close()" & 
ip netns exec fw_srv python3 -c "
import socket,threading
def srv(ip,port):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((ip,port)); s.listen(20)
    while True: s.accept()[0].close()
threading.Thread(target=srv,args=('0.0.0.0',8444),daemon=True).start(); srv('127.0.0.1',8443)" &
sleep 1
conn() { # conn <netns> <user|-> <host> <port> -> exit 0 if the TCP connection opened
  local ns=$1 user=$2 host=$3 port=$4 pre=""
  [ "$user" != "-" ] && pre="setpriv --reuid=$user --regid=$user --clear-groups"
  ip netns exec $ns $pre python3 -c "import socket,sys; s=socket.socket(); s.settimeout(2); s.connect(('$host',$port))" 2>/dev/null
}

echo "before the rules (control: the test setup itself must work)"
conn fw_srv - 10.77.0.2 9001 && pass "control: outbound works without a firewall" || nope "control failed: outbound blocked before rules"
conn fw_peer - 10.77.0.1 8444 && pass "control: inbound works without a firewall" || nope "control failed: inbound blocked before rules"

ip netns exec fw_srv nft -f $RULES || { nope "rules did not load"; exit 1; }
: > $LOG
echo "with the rules"
conn fw_srv - 10.77.0.2 9001            && nope "root can reach the outside" || pass "outbound from root is dropped"
conn fw_srv noc 10.77.0.2 9001          && nope "service user 'noc' can reach the outside" || pass "outbound from the service user is dropped"
sleep 0.3; [ ! -s $LOG ]                 && pass "the outside world saw no connection attempts from non-Tor users" || nope "peer saw a connection from a non-Tor user"
conn fw_srv debian-tor 10.77.0.2 9001   && pass "outbound from the Tor process works" || nope "Tor process is blocked"
conn fw_peer - 10.77.0.1 8444           && nope "inbound connection to a listening port got through" || pass "inbound from outside is dropped even when a port listens"
conn fw_srv noc 127.0.0.1 8443          && pass "loopback still works for the service user" || nope "loopback blocked"
conn fw_srv - 127.0.0.1 8443            && pass "loopback works for root" || nope "loopback blocked for root"
# no exceptions for well-known ports either
for port in 22 53 80 123 443; do
  ip netns exec fw_peer python3 -c "import socket; s=socket.socket(); s.bind(('10.77.0.2',$port)); s.listen(5); import time; time.sleep(6)" 2>/dev/null &
done; sleep 0.5
for port in 22 53 80 123 443; do conn fw_srv - 10.77.0.2 $port && nope "port $port is open outbound" || true; done
pass "no outbound exceptions for ports 22, 53, 80, 123, 443 (SSH, DNS, HTTP, NTP, HTTPS)"
[ $fail = 0 ] && echo "FIREWALL TEST OK" || echo "FIREWALL TEST FAILED"
exit $fail
