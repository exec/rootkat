#!/usr/bin/env bash
# Asserts: a Rust kernel module builds and loads cleanly on Linux 7.0.
# Independent of the C rootkat module — this just proves the build
# pipeline and runtime support are real.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

assert_zero    "rust ko exists"           test -f rust/rootkat_rust_hello.ko
assert_zero    "rust module loads"        insmod rust/rootkat_rust_hello.ko
assert_zero    "appears in /sys/module"   test -d /sys/module/rootkat_rust_hello
assert_zero    "appears in /proc/modules" \
	bash -c "grep -q '^rootkat_rust_hello ' /proc/modules"
assert_zero    "init message in dmesg"    \
	bash -c "dmesg | tail -50 | grep -q 'hello from rust on linux 7.0'"
assert_zero    "rust module unloads"      rmmod rootkat_rust_hello
assert_nonzero "gone from /sys/module"    test -d /sys/module/rootkat_rust_hello
assert_zero    "exit message in dmesg"    \
	bash -c "dmesg | tail -50 | grep -q 'rootkat_rust_hello.*goodbye'"

report
