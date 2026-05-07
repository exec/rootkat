#!/usr/bin/env bash
# Asserts: a TCP listener whose port is added to rootkat's hidden-ports
# list disappears from /proc/net/tcp (so ss/netstat/lsof can't see it),
# while the listener itself continues working.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

PORT=12345

assert_zero "module loads" insmod lkm/rootkat.ko

# --- Baseline: a non-hiding listener should be visible ------------------
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3   # waits for "ready"
BASELINE_PID=$!
sleep 0.2
assert_zero "baseline: ss shows port"     bash -c "ss -tln | grep -q ':$PORT '"
assert_zero "baseline: /proc/net/tcp has port" \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $PORT"
kill $BASELINE_PID 2>/dev/null || true
wait $BASELINE_PID 2>/dev/null || true
exec 3<&-
sleep 0.3   # let TIME_WAIT settle so the rebind on the same port works

# --- Hide-mode listener: should be invisible to ss/netstat --------------
exec 3< <(tests/qemu/net_helper $PORT hide)
read -r LINE <&3   # "ready" arrives only after the hide kill() returns
HIDE_PID=$!
sleep 0.2

assert_nonzero "hidden: ss does NOT show port"     bash -c "ss -tln | grep -q ':$PORT '"
assert_nonzero "hidden: /proc/net/tcp omits port"  \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $PORT"

# Direct connect must still work — we hide from enumeration only.
assert_zero "hidden: still connectable" \
	bash -c "exec 4<>/dev/tcp/127.0.0.1/$PORT && exec 4<&- 4>&-"

kill $HIDE_PID 2>/dev/null || true
wait $HIDE_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat

# --- Post-unload: visibility restored -----------------------------------
sleep 0.3
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3
POST_PID=$!
sleep 0.2
assert_zero "post-unload: ss shows port" bash -c "ss -tln | grep -q ':$PORT '"
kill $POST_PID 2>/dev/null || true
wait $POST_PID 2>/dev/null || true
exec 3<&-

report
