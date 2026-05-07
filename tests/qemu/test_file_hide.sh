#!/usr/bin/env bash
# Asserts: with the eBPF loader running, /tmp/secret.txt is invisible.
#
# Requires: `bpf` in the kernel's lsm= boot parameter. Ubuntu 26.04's
# default cmdline is `lockdown,capability,landlock,yama,apparmor,ima,evm`
# (no bpf), so BPF LSM hooks attach but never fire. Skip this test on
# such kernels — the asserted invariant is unreachable until the boot
# parameter is changed.
#
# TODO(rootkat): drive the kernel cmdline change from cloud-init in
# run.sh (write /etc/default/grub.d/99-bpf-lsm.cfg, update-grub, reboot).
# Until then, this test is a no-op on the default Ubuntu image and the
# real validation lives in manual runs against a kernel with lsm=...,bpf.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

if ! grep -q '\bbpf\b' /sys/kernel/security/lsm 2>/dev/null; then
	echo "SKIP: bpf not in /sys/kernel/security/lsm"
	echo "  current: $(cat /sys/kernel/security/lsm 2>/dev/null || echo MISSING)"
	echo "  fix: add 'bpf' to lsm= kernel cmdline (TODO in test header)"
	# Sanity-check that the loader at least builds and attaches cleanly
	# even if the hook can't fire — catches regressions in libbpf use.
	echo "secret" > /tmp/secret.txt
	cd ebpf
	./loader secret.txt > /tmp/loader.log 2>&1 &
	LOADER_PID=$!
	sleep 2
	cd ..
	assert_zero    "loader still attached"  kill -0 $LOADER_PID
	kill -INT $LOADER_PID 2>/dev/null || true
	wait $LOADER_PID 2>/dev/null || true
	report
	exit
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
