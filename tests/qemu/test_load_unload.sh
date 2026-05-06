#!/usr/bin/env bash
# Runs INSIDE the VM. Assets at /root/rootkat/.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero "module loads"   insmod lkm/rootkat.ko
assert_zero "module appears" grep -q '^rootkat ' /proc/modules
assert_zero "module unloads" rmmod rootkat
assert_nonzero "module gone" grep -q '^rootkat ' /proc/modules

report
