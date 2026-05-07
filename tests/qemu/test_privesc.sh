#!/usr/bin/env bash
# Asserts: kill(getpid(), 64) elevates a non-root caller to euid=0
# when the rootkat module is loaded.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero "module loads"           insmod lkm/rootkat.ko
assert_zero "privesc helper exists"  test -x tests/qemu/privesc_helper

# Helper self-drops to nobody, sends magic signal, checks euid==0.
assert_zero "privesc via magic sig"  tests/qemu/privesc_helper

assert_zero "module unloads"         rmmod rootkat

# After unload, the hook is gone — the same helper should NOT escalate.
# (We invoke it again and expect failure.)
if tests/qemu/privesc_helper >/dev/null 2>&1; then
	echo "FAIL: privesc still works after rmmod (hook leaked?)"
	ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
else
	echo "PASS: privesc no longer works after rmmod"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
fi

report
