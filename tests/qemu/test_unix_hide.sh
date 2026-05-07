#!/usr/bin/env bash
# Asserts: an AF_UNIX listener bound to a path containing the rootkat
# stealth marker (".rootkat") disappears from /proc/net/unix, while a
# normal listener stays visible. After unload, the hidden listener is
# visible again.
#
# /proc/net/unix is the dominant detection surface — used by lsof -U,
# any /proc walker, and older socket inventories. The NETLINK_SOCK_DIAG
# (`ss -lx`) path is NOT covered in v0.7 — see docs/threat-model.md
# for the explicit gap. We don't assert against it here because the
# behavior is documented-as-broken until v0.8.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

VISIBLE_PATH=/tmp/normal-listener.sock
HIDDEN_PATH=/tmp/.rootkat-secret.sock

unix_paths_in_proc() {
	# /proc/net/unix columns: Num RefCount Protocol Flags Type St Inode Path
	# The Path column is optional — only socketpair() and unbound sockets
	# omit it. We print every populated Path.
	awk 'NR>1 && NF>=8 {for (i=8;i<=NF;i++) printf "%s ", $i; print ""}' /proc/net/unix
}

assert_zero "module loads" insmod lkm/rootkat.ko

# --- Visible path: appears in /proc/net/unix ---------------------------
exec 3< <(tests/qemu/unix_helper $VISIBLE_PATH)
read -r LINE <&3
VISIBLE_PID=$!
sleep 0.2
assert_zero "baseline: visible socket in /proc/net/unix" \
	bash -c "$(declare -f unix_paths_in_proc); unix_paths_in_proc | grep -qF $VISIBLE_PATH"

# --- Hidden path: NOT in /proc/net/unix --------------------------------
exec 4< <(tests/qemu/unix_helper $HIDDEN_PATH)
read -r LINE <&4
HIDDEN_PID=$!
sleep 0.2
assert_nonzero "hidden: rootkat path NOT in /proc/net/unix" \
	bash -c "$(declare -f unix_paths_in_proc); unix_paths_in_proc | grep -qF $HIDDEN_PATH"

# Direct connect must still work — we hide from enumeration, not from
# anything that already knows the path. Bash redirection doesn't speak
# AF_UNIX, so use python3 (present in the cloud image base).
assert_zero "hidden: still connectable via known path" \
	python3 -c "import socket;s=socket.socket(socket.AF_UNIX);s.connect('$HIDDEN_PATH');s.close()"

# --- Visible socket from same time still visible -----------------------
assert_zero "visible socket stays visible after hidden bind" \
	bash -c "$(declare -f unix_paths_in_proc); unix_paths_in_proc | grep -qF $VISIBLE_PATH"

kill $HIDDEN_PID 2>/dev/null || true
wait $HIDDEN_PID 2>/dev/null || true
exec 4<&-

kill $VISIBLE_PID 2>/dev/null || true
wait $VISIBLE_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat

# --- Post-unload: visibility restored ----------------------------------
sleep 0.3
exec 3< <(tests/qemu/unix_helper $HIDDEN_PATH)
read -r LINE <&3
POST_PID=$!
sleep 0.2
assert_zero "post-unload: hidden path now visible in /proc/net/unix" \
	bash -c "$(declare -f unix_paths_in_proc); unix_paths_in_proc | grep -qF $HIDDEN_PATH"
kill $POST_PID 2>/dev/null || true
wait $POST_PID 2>/dev/null || true
exec 3<&-

report
