#!/usr/bin/env bash
# Asserts: with the eBPF loader running, /tmp/secret.txt is invisible.
#
# Requires `bpf` in the kernel's lsm= cmdline. The QEMU harness drives a
# GRUB drop-in + reboot in cloud-init so this is true by the time the
# test runs. If we ever boot without it (manual runs) the assertions
# below will fail loudly rather than silently — that's intentional.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

if ! grep -qw bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "FAIL: bpf not in /sys/kernel/security/lsm — harness should have"
	echo "      rewritten GRUB and rebooted before running this test."
	echo "      current: $(cat /sys/kernel/security/lsm 2>/dev/null || echo MISSING)"
	exit 1
fi

echo "secret" > /tmp/secret.txt

assert_zero    "baseline: cat reads it"  cat /tmp/secret.txt

cd ebpf
./loader secret.txt > /tmp/loader.log 2>&1 &
LOADER_PID=$!
sleep 2
cd ..

assert_nonzero "hidden: cat fails"       cat /tmp/secret.txt
assert_zero    "other files unaffected"  test -f /etc/hostname

if [ "$ROOTKAT_FAIL" -gt 0 ]; then
	echo "=== loader log ==="
	cat /tmp/loader.log || true
	echo "=== bpftool link list ==="
	bpftool link list 2>&1 | tail -20
	echo "=== dmesg tail ==="
	dmesg | tail -30 || true
fi

kill -INT $LOADER_PID 2>/dev/null || true
wait $LOADER_PID 2>/dev/null || true
sleep 1

assert_zero    "restored: cat works"     cat /tmp/secret.txt

report
