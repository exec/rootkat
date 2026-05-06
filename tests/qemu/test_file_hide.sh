#!/usr/bin/env bash
# Asserts: with the eBPF loader running, /tmp/secret.txt is invisible.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

# Need BPF LSM enabled. Ubuntu 26.04 has it on by default.
echo "secret" > /tmp/secret.txt

assert_zero    "baseline: cat reads it"  cat /tmp/secret.txt

cd ebpf
./loader secret.txt &
LOADER_PID=$!
sleep 1
cd ..

assert_nonzero "hidden: cat fails"       cat /tmp/secret.txt
assert_zero    "other files unaffected"  test -f /etc/hostname

kill -INT $LOADER_PID 2>/dev/null || true
wait $LOADER_PID 2>/dev/null || true
sleep 1

assert_zero    "restored: cat works"     cat /tmp/secret.txt

report
