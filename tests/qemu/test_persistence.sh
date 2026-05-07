#!/usr/bin/env bash
# Asserts: rootkat persistently auto-loads on boot via the install.sh
# systemd unit. Two-phase test using a marker file in /var/lib that
# survives the in-VM reboot (qcow2 snapshot=on overlay persists across
# guest reboots within one QEMU invocation; discarded when QEMU exits).
set -u
cd /root/rootkat
. tests/qemu/lib.sh

MARKER=/var/lib/rootkat-test-installed

if [ ! -e "$MARKER" ]; then
	# === Phase 1: install rootkat, mark, reboot ===
	echo "=== persistence phase 1: installing ==="

	# Sanity: rootkat is not loaded yet.
	if [ -d /sys/module/rootkat ]; then
		echo "FAIL phase1: rootkat already loaded before install"
		exit 1
	fi

	bash scripts/install.sh

	# Verify the install dropped the expected artifacts.
	if [ ! -f /usr/local/lib/rootkat/rootkat.ko ]; then
		echo "FAIL phase1: /usr/local/lib/rootkat/rootkat.ko missing"
		exit 1
	fi
	if ! systemctl is-enabled rootkat-lkm.service >/dev/null; then
		echo "FAIL phase1: rootkat-lkm.service not enabled"
		exit 1
	fi

	mkdir -p "$(dirname $MARKER)"
	touch "$MARKER"
	sync

	echo "=== rebooting guest to verify auto-load ==="
	# Reboot. Sleep keeps the script alive long enough for systemd to
	# tear down — without it, the script would exit, runtest.sh would
	# write rc=0 and poweroff, and we'd never get the second boot.
	systemctl reboot
	sleep 120
	echo "FAIL phase1: reboot did not take effect within 120s"
	exit 1
fi

# === Phase 2: post-reboot verification ===
echo "=== persistence phase 2: verifying auto-load ==="

# rootkat-lkm.service ran early in boot; rootkat should be active.
assert_zero    "phase2: /sys/module/rootkat exists"  test -d /sys/module/rootkat
assert_nonzero "phase2: still hidden from /proc/modules" \
	grep -q '^rootkat ' /proc/modules

# Hooks active: the hide-self magic signal still works post-reboot.
exec 3< <(tests/qemu/hide_helper)
read -r HELPER_PID <&3
sleep 0.5
assert_nonzero "phase2: hide signal still works after reboot" \
	bash -c "ls /proc | grep -qx $HELPER_PID"
kill $HELPER_PID 2>/dev/null || true
wait $HELPER_PID 2>/dev/null || true
exec 3<&-

# Uninstall: service disabled, files removed, module unloaded.
bash scripts/uninstall.sh
assert_nonzero "phase2: module unloaded after uninstall" \
	test -d /sys/module/rootkat
assert_nonzero "phase2: install dir removed" \
	test -d /usr/local/lib/rootkat
rm -f "$MARKER"

report
