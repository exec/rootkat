#!/usr/bin/env bash
# Asserts: the Rust LKM (rootkat_rust_canary) builds and loads cleanly,
# and rootkat.ko's weak-linked init path picks up its exported tick()
# symbol, incrementing the canary counter once per insmod.
#
# Skipped (rc=0) on kernels without lib-rust (e.g. Ubuntu 24.04 / 6.8)
# — rust/Makefile no-ops and the .ko isn't built. The C side's weak
# symbol logs "rust canary not loaded (C-only build)" instead.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

if [ ! -f rust/rootkat_rust_canary.ko ]; then
    echo "SKIP: rust/rootkat_rust_canary.ko was not built (kernel has no lib-rust)"
    exit 0
fi

dmesg -c >/dev/null 2>&1 || true

assert_zero    "canary ko exists"           test -f rust/rootkat_rust_canary.ko
assert_zero    "canary loads"               insmod rust/rootkat_rust_canary.ko
assert_zero    "appears in /sys/module"     test -d /sys/module/rootkat_rust_canary
assert_zero    "appears in /proc/modules"   \
	bash -c "grep -q '^rootkat_rust_canary ' /proc/modules"
assert_zero    "armed message in dmesg"     \
	bash -c "dmesg | tail -50 | grep -q 'rootkat_rust_canary: armed'"

# Now load the C module — it should call rust_canary_tick() at init via
# the weak-linked extern. dmesg should show both the canary tick and
# the C side picking up a non-NULL symbol.
assert_zero    "rootkat (C) loads"          insmod lkm/rootkat.ko
assert_zero    "canary tick #1 in dmesg"    \
	bash -c "dmesg | tail -100 | grep -q 'rootkat_rust_canary: tick #1'"
assert_zero    "C side saw canary present"  \
	bash -c "dmesg | tail -100 | grep -q 'rootkat: rust canary present, tick=1'"
assert_zero    "rootkat (C) unloads"        rmmod rootkat

# Reload C module — canary value should bump to 2.
assert_zero    "rootkat (C) reloads"        insmod lkm/rootkat.ko
assert_zero    "canary tick #2 in dmesg"    \
	bash -c "dmesg | tail -100 | grep -q 'rootkat_rust_canary: tick #2'"
assert_zero    "rootkat (C) unloads again"  rmmod rootkat

assert_zero    "canary unloads"             rmmod rootkat_rust_canary
assert_nonzero "gone from /sys/module"      test -d /sys/module/rootkat_rust_canary
assert_zero    "disarmed final=2 in dmesg"  \
	bash -c "dmesg | tail -50 | grep -q 'rootkat_rust_canary: disarmed (final counter=2)'"

# After the canary is gone, rootkat (C) should fall back to the "C-only"
# branch — weak symbols become NULL once the providing module unloaded.
assert_zero    "rootkat (C) loads C-only"   insmod lkm/rootkat.ko
assert_zero    "C-only branch in dmesg"     \
	bash -c "dmesg | tail -50 | grep -q 'rootkat: rust canary not loaded'"
assert_zero    "rootkat unloads"            rmmod rootkat

report
