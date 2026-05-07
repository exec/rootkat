#!/usr/bin/env bash
# Asserts: a Rust kernel module builds and loads cleanly on a kernel
# with lib-rust support. Independent of the C rootkat module — this
# just proves the build pipeline and runtime support are real.
#
# Skipped (rc=0) on kernels without lib-rust (e.g. Ubuntu 24.04 / 6.8)
# — rust/Makefile no-ops and rootkat_rust_hello.ko isn't built.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

if [ ! -f rust/rootkat_rust_hello.ko ]; then
    echo "SKIP: rust/rootkat_rust_hello.ko was not built (kernel has no lib-rust)"
    exit 0
fi

assert_zero    "rust ko exists"           test -f rust/rootkat_rust_hello.ko
assert_zero    "rust module loads"        insmod rust/rootkat_rust_hello.ko
assert_zero    "appears in /sys/module"   test -d /sys/module/rootkat_rust_hello
assert_zero    "appears in /proc/modules" \
	bash -c "grep -q '^rootkat_rust_hello ' /proc/modules"
assert_zero    "init message in dmesg"    \
	bash -c "dmesg | tail -50 | grep -q 'rootkat rust LKM init'"
assert_zero    "rust module unloads"      rmmod rootkat_rust_hello
assert_nonzero "gone from /sys/module"    test -d /sys/module/rootkat_rust_hello
assert_zero    "exit message in dmesg"    \
	bash -c "dmesg | tail -50 | grep -q 'rootkat_rust_hello.*goodbye'"

report
