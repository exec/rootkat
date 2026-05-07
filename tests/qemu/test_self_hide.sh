#!/usr/bin/env bash
# Asserts: after loading rootkat, /proc/modules does NOT list it.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero    "module loads"             insmod lkm/rootkat.ko
assert_nonzero "module hidden in /proc"   grep -q '^rootkat ' /proc/modules

# /sys/module/rootkat directory still exists for direct access (rmmod
# uses /sys/module/<name>/holders etc.), but the entry should be filtered
# out of `ls /sys/module/` enumeration via the filldir64 self-hide.
assert_zero    "module still alive"       test -d /sys/module/rootkat
assert_nonzero "module hidden in sysfs"   bash -c "ls /sys/module/ | grep -qx rootkat"

# rmmod by name still works (looks up by name, not enumeration).
assert_zero    "module unloads"           rmmod rootkat

report
