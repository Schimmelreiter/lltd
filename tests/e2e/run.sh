#!/bin/sh
# End-to-end test with real sockets in network namespaces (needs root,
# iproute2, python3; tcpdump optional for the pcap captures).
#
#   mapper --- sw0 (switch) --- r1
#                 |
#                 +--- router: br-lan (bridge, like OpenWrt) --- r2
#
# lltd runs on r1 (eth0), on the router (br-lan) and on r2 (eth0).
# Round 1: c = router, d = r2. r2's probe to the test address X only reaches
#          the router if the router's bridge delivers X locally (FDB entry
#          added for the Train source) - without it the round is INVALID.
# Round 2: c = r1, d = r2 (plain host as c).
#
# Usage: tests/e2e/run.sh [extra lltd options for the router, e.g. --no-fdb]
# Captures and logs: tests/out/e2e-*.pcap, tests/out/e2e-*.log

set -u
cd "$(dirname "$0")/../.."
LLTD=$(pwd)/lltd
OUT=$(pwd)/tests/out
mkdir -p "$OUT"
NS="lm lr1 lrt lr2"

cleanup() {
	for n in $NS; do
		ip netns pids "$n" 2>/dev/null | xargs -r kill 2>/dev/null
	done
	sleep 0.3
	for n in $NS; do ip netns del "$n" 2>/dev/null; done
	ip link del sw0 2>/dev/null
	for l in vm vr1 vrt; do ip link del "$l" 2>/dev/null; done
}
trap cleanup EXIT INT TERM
cleanup

for n in $NS; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip link add sw0 type bridge && ip link set sw0 up

link_ns() {    # <host side> <ns> <ns side>
	ip link add "$1" type veth peer name "$3" netns "$2"
	ip link set "$1" master sw0 up
	ip -n "$2" link set "$3" up
}
link_ns vm lm eth0
link_ns vr1 lr1 eth0
link_ns vrt lrt lan1
ip -n lrt link add br-lan type bridge
ip -n lrt link set lan1 master br-lan
ip -n lrt link add lan2 type veth peer name eth0 netns lr2
ip -n lrt link set lan2 master br-lan up
ip -n lrt link set br-lan up
ip -n lr2 link set eth0 up
ip -n lr1 addr add 192.168.99.11/24 dev eth0
ip -n lrt addr add 192.168.99.1/24 dev br-lan
ip -n lr2 addr add 192.168.99.12/24 dev eth0
sleep 1

if command -v tcpdump >/dev/null; then
	ip netns exec lm tcpdump -q -i eth0 -w "$OUT/e2e-mapper.pcap" ether proto 0x88d9 2>/dev/null &
	ip netns exec lrt tcpdump -q -i br-lan -w "$OUT/e2e-router.pcap" ether proto 0x88d9 2>/dev/null &
fi
ip netns exec lr1 "$LLTD" -f -vvv -i eth0 -H r1 > "$OUT/e2e-r1.log" 2>&1 &
ip netns exec lrt "$LLTD" -f -vvv -i br-lan -H router --nat-private -w "$@" > "$OUT/e2e-router.log" 2>&1 &
ip netns exec lr2 "$LLTD" -f -vvv -i eth0 -H r2 > "$OUT/e2e-r2.log" 2>&1 &
sleep 1

mac() { ip -n "$1" link show "$2" | awk '/link\/ether/ { print $2 }'; }
R1=$(mac lr1 eth0); RT=$(mac lrt br-lan); R2=$(mac lr2 eth0)
echo "r1=$R1 router=$RT r2=$R2"

ip netns exec lm python3 tests/e2e/mapper.py eth0 "$RT,$R2" "$R1,$R2"
rc=$?
sleep 0.5
echo "router bridge FDB entries (permanent) from the LLTD address pool after the Reset:"
ip netns exec lrt bridge fdb show br br-lan | grep -i '^00:0d:3a' | grep -i permanent || echo "  (none)"
[ "$rc" = 0 ] && echo "E2E: PASS" || echo "E2E: FAIL"
exit "$rc"
