#!/bin/sh
# Reproducible throughput check for two vpncloud nodes in network namespaces.
# Requires: sudo, ip, iperf3. Run from the repository root.
#
#   sudo ./bench/run.sh [release|dist]
#
# Creates two namespaces joined by a veth pair, runs a TUN VPN between them,
# then measures TCP and UDP with iperf3. Prints the same rows used in README.md.
set -eu

PROFILE=${1:-release}
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BIN="$ROOT/target/$PROFILE/vpncloud"

if [ ! -x "$BIN" ]; then
  echo "Build first: cargo build --$PROFILE --features installer" >&2
  exit 1
fi
for tool in ip iperf3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "Missing $tool" >&2; exit 1; }
done

cleanup() {
  ip netns del vc1 2>/dev/null || true
  ip netns del vc2 2>/dev/null || true
  [ -n "${LOG1:-}" ] && rm -f "$LOG1" || true
  [ -n "${LOG2:-}" ] && rm -f "$LOG2" || true
}
trap cleanup EXIT INT TERM
cleanup

ip netns add vc1
ip netns add vc2
ip link add vc1eth type veth peer name vc2eth
ip link set vc1eth netns vc1
ip link set vc2eth netns vc2
ip -n vc1 addr add 192.168.88.2/24 dev vc1eth
ip -n vc1 link set vc1eth up
ip -n vc2 addr add 192.168.88.3/24 dev vc2eth
ip -n vc2 link set vc2eth up

LOG1=$(mktemp)
LOG2=$(mktemp)
PASSWORD=bench-secret

ip netns exec vc1 "$BIN" --type tun --ip 10.99.0.1/24 -p "$PASSWORD" \
  --listen 3310 -c 192.168.88.3:3311 >"$LOG1" 2>&1 &
ip netns exec vc2 "$BIN" --type tun --ip 10.99.0.2/24 -p "$PASSWORD" \
  --listen 3311 -c 192.168.88.2:3310 >"$LOG2" 2>&1 &
sleep 2

echo "=== TCP (10.99.0.2 -> 10.99.0.1) ==="
ip netns exec vc1 iperf3 -s -p 5201 >/dev/null 2>&1 &
sleep 1
ip netns exec vc2 iperf3 -c 10.99.0.1 -p 5201 -t 10

echo "=== UDP (unlimited offer) ==="
ip netns exec vc1 iperf3 -s -p 5202 >/dev/null 2>&1 &
sleep 1
ip netns exec vc2 iperf3 -c 10.99.0.1 -p 5202 -u -b 0 -t 10

echo "=== Node logs (tails) ==="
tail -5 "$LOG1"
tail -5 "$LOG2"
