#!/usr/bin/env bash
# Boot QEMU with the Ubuntu 26.04 image, copy the rootkat tree in via 9p,
# run the named test script, return its exit code.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_SCRIPT="${1:?usage: run.sh tests/qemu/test_*.sh}"
IMG="$ROOT/tests/qemu/images/ubuntu-26.04.img"

if [ ! -f "$IMG" ]; then
	"$ROOT/scripts/fetch_test_image.sh"
fi

# QEMU shares the host rootkat tree at /root/rootkat via virtio-9p.
# cloud-init runs the test script on first boot and writes the result to
# a shared file; the host reads it and exits with that status.

RESULT_FILE="$(mktemp)"
trap "rm -f $RESULT_FILE" EXIT

CLOUD_INIT_DIR="$(mktemp -d)"
trap "rm -rf $CLOUD_INIT_DIR" EXIT

cat > "$CLOUD_INIT_DIR/user-data" <<EOF
#cloud-config
runcmd:
  - mkdir -p /root/rootkat
  - mount -t 9p -o trans=virtio,version=9p2000.L rootkat /root/rootkat
  - mount -t 9p -o trans=virtio,version=9p2000.L result /mnt/result
  - bash /root/rootkat/$TEST_SCRIPT > /mnt/result/log 2>&1; echo \$? > /mnt/result/rc
  - poweroff
EOF
echo "instance-id: rootkat-test" > "$CLOUD_INIT_DIR/meta-data"

RESULT_DIR="$(mktemp -d)"
trap "rm -rf $RESULT_DIR" EXIT

cloud-localds "$CLOUD_INIT_DIR/seed.img" "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data"

qemu-system-x86_64 \
    -enable-kvm -cpu host -m 2048 -smp 2 \
    -drive if=virtio,file="$IMG",format=qcow2,snapshot=on \
    -drive if=virtio,file="$CLOUD_INIT_DIR/seed.img",format=raw \
    -fsdev local,id=rootkat,path="$ROOT",security_model=none \
    -device virtio-9p-pci,fsdev=rootkat,mount_tag=rootkat \
    -fsdev local,id=result,path="$RESULT_DIR",security_model=none \
    -device virtio-9p-pci,fsdev=result,mount_tag=result \
    -nographic -serial mon:stdio -no-reboot

cat "$RESULT_DIR/log"
exit "$(cat $RESULT_DIR/rc)"
