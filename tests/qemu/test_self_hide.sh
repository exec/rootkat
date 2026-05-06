#!/usr/bin/env bash
# Asserts: after loading rootkat, /proc/modules does NOT list it.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero    "module loads"            insmod lkm/rootkat.ko
assert_nonzero "module hidden in /proc"  grep -q '^rootkat ' /proc/modules
assert_zero    "module still alive"      test -d /sys/module/rootkat
# Cleanup: rmmod by name still works since we did not unlink from the
# module hash, only suppressed m_show output.
assert_zero    "module unloads"          rmmod rootkat

report
