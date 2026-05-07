#!/usr/bin/env bash
# Asserts: an AF_UNIX listener bound to a path containing the rootkat
# stealth marker (".rootkat") disappears from /proc/net/unix AND from
# `ss -lx` (NETLINK_SOCK_DIAG path), while a normal listener stays
# visible. After unload, the hidden listener is visible again.
#
# /proc/net/unix is hooked at unix_seq_show; the netlink path is
# hooked at unix_diag's static sk_diag_fill, resolved via the
# module-scoped kallsyms resolver primitive (kallsyms_on_each_symbol
# + __module_address) so the same-named static in inet_diag /
# raw_diag doesn't get confused with it.
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

# Netlink path: ss -lx walks NETLINK_SOCK_DIAG → unix_diag's static
# sk_diag_fill. Our hook (resolved via module-scoped kallsyms lookup
# to avoid the inet_diag/raw_diag collision) skips the matching socket.
assert_nonzero "hidden: ss -lx omits rootkat path (netlink hook)" \
	bash -c "ss -lx | grep -qF $HIDDEN_PATH"

# Sanity: ss -lx still shows the visible socket — we only filter the
# matching path, not all AF_UNIX entries.
assert_zero "ss -lx still shows visible socket" \
	bash -c "ss -lx | grep -qF $VISIBLE_PATH"

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
