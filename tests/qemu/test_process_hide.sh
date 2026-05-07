#!/usr/bin/env bash
# Asserts: after a process sends the rootkat hide signal to itself, its
# PID disappears from `ls /proc` and `ps`, while /proc/<pid> remains
# accessible by direct stat.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero "module loads" insmod lkm/rootkat.ko

# Spawn helper in background. It prints its PID, sends hide signal to
# itself, then pauses. Read the PID from stdout (line-buffered).
exec 3< <(tests/qemu/hide_helper)
read -r HELPER_PID <&3
echo "helper pid: $HELPER_PID"
sleep 0.5

assert_zero    "direct: /proc/<pid> accessible" test -d /proc/$HELPER_PID
assert_nonzero "hidden: pid not in ls /proc"    \
	bash -c "ls /proc | grep -qx $HELPER_PID"
assert_nonzero "hidden: ps doesn't list it"     \
	bash -c "ps -e -o pid= | tr -d ' ' | grep -qx $HELPER_PID"

# Cleanup helper.
kill $HELPER_PID 2>/dev/null || true
wait $HELPER_PID 2>/dev/null || true
exec 3<&-

assert_zero "module unloads" rmmod rootkat

# After unload, an unrelated background process's PID must be visible.
# (Don't use hide_helper here — without our hook intercepting it, signal
# 63 = SIGRTMAX-1 has default-terminate disposition and would kill the
# helper before we get to check.)
sleep 30 &
SECOND_PID=$!
sleep 0.2
assert_zero "post-unload: pid visible in ls" \
	bash -c "ls /proc | grep -qx $SECOND_PID"
kill $SECOND_PID 2>/dev/null || true
wait $SECOND_PID 2>/dev/null || true

report
