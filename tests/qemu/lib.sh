# Shared QEMU test helpers. Sourced by test scripts running INSIDE the VM.
# Each helper prints pass/fail and increments counters; the script exits
# nonzero if any assertion failed.

ROOTKAT_PASS=0
ROOTKAT_FAIL=0

assert_zero() {
	local desc="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "PASS: $desc"
		ROOTKAT_PASS=$((ROOTKAT_PASS+1))
	else
		echo "FAIL: $desc (rc=$?)"
		ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
	fi
}

assert_nonzero() {
	local desc="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "FAIL: $desc (expected nonzero rc, got 0)"
		ROOTKAT_FAIL=$((ROOTKAT_FAIL+1))
	else
		echo "PASS: $desc"
		ROOTKAT_PASS=$((ROOTKAT_PASS+1))
	fi
}

report() {
	echo "----"
	echo "passed: $ROOTKAT_PASS"
	echo "failed: $ROOTKAT_FAIL"
	[ "$ROOTKAT_FAIL" -eq 0 ]
}
