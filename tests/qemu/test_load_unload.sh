#!/usr/bin/env bash
# Runs INSIDE the VM. Assets at /root/rootkat/.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

# Smoke test: insmod + rmmod work. /proc/modules visibility is asserted
# separately by test_self_hide.sh (the module self-hides on load by design,
# so a "module appears in /proc/modules" check belongs only there).
dmesg -c >/dev/null 2>&1 || true
if ! insmod lkm/rootkat.ko 2>&1; then
    echo "FAIL: insmod (see dmesg below):"
    dmesg | tail -40
    ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
else
    echo "PASS: module loads"
    ROOTKAT_PASS=$((ROOTKAT_PASS+1))
fi
assert_zero    "module unloads" rmmod rootkat
assert_nonzero "module gone"    grep -q '^rootkat ' /proc/modules

report
