#!/usr/bin/env bash
# Asserts: with the eBPF loader running, /tmp/secret.txt is invisible.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

echo "=== environment ==="
echo "lsm: $(cat /sys/kernel/security/lsm 2>/dev/null || echo MISSING)"
echo "cmdline: $(cat /proc/cmdline)"
echo "uname: $(uname -r)"
echo "kernel.unprivileged_bpf_disabled: $(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo MISSING)"
echo "id: $(id)"

echo "secret" > /tmp/secret.txt

assert_zero    "baseline: cat reads it"  cat /tmp/secret.txt

cd ebpf
./loader secret.txt > /tmp/loader.log 2>&1 &
LOADER_PID=$!
sleep 2
cd ..

echo "=== loader log ==="
cat /tmp/loader.log || true
echo "=== loader still running? ==="
kill -0 $LOADER_PID 2>/dev/null && echo "yes (pid $LOADER_PID)" || echo "NO — loader exited"
echo "=== bpftool prog list ==="
bpftool prog list 2>&1 | tail -20
echo "=== bpftool link list ==="
bpftool link list 2>&1 | tail -20

assert_nonzero "hidden: cat fails"       cat /tmp/secret.txt
assert_zero    "other files unaffected"  test -f /etc/hostname

if [ "$ROOTKAT_FAIL" -gt 0 ]; then
	echo "=== dmesg tail ==="
	dmesg | tail -30 || true
fi

kill -INT $LOADER_PID 2>/dev/null || true
wait $LOADER_PID 2>/dev/null || true
sleep 1

assert_zero    "restored: cat works"     cat /tmp/secret.txt

report
