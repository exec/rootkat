#!/usr/bin/env bash
# Boot QEMU with the Ubuntu 26.04 image, copy the rootkat tree in via 9p,
# run the named test script, return its exit code.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_SCRIPT="${1:?usage: run.sh tests/qemu/test_*.sh}"
IMG="$ROOT/tests/qemu/images/ubuntu-26.04.img"
TIMEOUT_SECS="${TIMEOUT_SECS:-300}"

# Preflight: required tools and KVM access. Fail loudly with a clear message
# rather than letting QEMU/cloud-localds print walls of opaque error.
for tool in qemu-system-x86_64 cloud-localds timeout; do
    command -v "$tool" >/dev/null \
        || { echo "missing tool: $tool" >&2; exit 2; }
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || { echo "no /dev/kvm access (KVM-capable Linux host required)" >&2; exit 2; }

if [ ! -f "$IMG" ]; then
    "$ROOT/scripts/fetch_test_image.sh"
fi

# Single trap that cleans every tmpdir we make. Multiple `trap ... EXIT`
# statements would each REPLACE the previous, leaking earlier paths.
CLEANUP=()
trap 'rm -rf "${CLEANUP[@]}"' EXIT

CLOUD_INIT_DIR="$(mktemp -d)"; CLEANUP+=("$CLOUD_INIT_DIR")
RESULT_DIR="$(mktemp -d)";     CLEANUP+=("$RESULT_DIR")

# QEMU shares the host rootkat tree at /root/rootkat via virtio-9p.
# cloud-init runs the test script on first boot and writes log + rc to
# the second 9p mount; the host reads rc and exits with that status.
cat > "$CLOUD_INIT_DIR/user-data" <<EOF
#cloud-config
network: {config: disabled}
runcmd:
  - mkdir -p /root/rootkat /mnt/result
  - mount -t 9p -o trans=virtio,version=9p2000.L rootkat /root/rootkat
  - mount -t 9p -o trans=virtio,version=9p2000.L result /mnt/result
  - bash /root/rootkat/$TEST_SCRIPT > /mnt/result/log 2>&1; echo \$? > /mnt/result/rc
  - poweroff
EOF
echo "instance-id: rootkat-test" > "$CLOUD_INIT_DIR/meta-data"

cloud-localds "$CLOUD_INIT_DIR/seed.img" \
    "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data"

# Wrap QEMU in `timeout` so a hung VM fails the test instead of running
# until the CI job's own timeout. `|| true` because QEMU's own exit code
# is not what we care about — the rc file inside the VM is.
timeout "$TIMEOUT_SECS" qemu-system-x86_64 \
    -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive if=virtio,file="$IMG",format=qcow2,snapshot=on \
    -drive if=virtio,file="$CLOUD_INIT_DIR/seed.img",format=raw \
    -fsdev local,id=rootkat,path="$ROOT",security_model=none \
    -device virtio-9p-pci,fsdev=rootkat,mount_tag=rootkat \
    -fsdev local,id=result,path="$RESULT_DIR",security_model=none \
    -device virtio-9p-pci,fsdev=result,mount_tag=result \
    -nographic -serial mon:stdio -no-reboot \
    || true

[ -s "$RESULT_DIR/log" ] && cat "$RESULT_DIR/log"

if [ ! -s "$RESULT_DIR/rc" ]; then
    echo "FATAL: VM did not produce result (panic / hang / timeout after ${TIMEOUT_SECS}s)" >&2
    exit 99
fi

rc="$(cat "$RESULT_DIR/rc")"
case "$rc" in
    ''|*[!0-9]*) echo "FATAL: invalid rc '$rc'" >&2; exit 98 ;;
esac
exit "$rc"
