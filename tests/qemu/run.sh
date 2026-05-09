#!/usr/bin/env bash
# Boot QEMU with an Ubuntu cloud image, copy the rootkat tree in via 9p,
# run the named test script, return its exit code.
#   $UBUNTU_VERSION (env, default 26.04) selects which image to boot.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEST_SCRIPT="${1:?usage: run.sh tests/qemu/test_*.sh}"
UBUNTU_VERSION="${UBUNTU_VERSION:-26.04}"
TIMEOUT_SECS="${TIMEOUT_SECS:-420}"
ARCH="${ARCH:-amd64}"

# Preflight: required tools and KVM access. Fail loudly with a clear message
# rather than letting QEMU/cloud-localds print walls of opaque error.
if [ "$ARCH" = "arm64" ]; then
    QEMU_BIN="qemu-system-aarch64"
else
    QEMU_BIN="qemu-system-x86_64"
fi
for tool in "$QEMU_BIN" cloud-localds timeout; do
    command -v "$tool" >/dev/null \
        || { echo "missing tool: $tool" >&2; exit 2; }
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] \
    || { echo "no /dev/kvm access (KVM-capable Linux host required)" >&2; exit 2; }

IMG="$("$ROOT/scripts/fetch_test_image.sh" "$UBUNTU_VERSION")"

# Single trap that cleans every tmpdir we make. Multiple `trap ... EXIT`
# statements would each REPLACE the previous, leaking earlier paths.
CLEANUP=()
trap 'rm -rf "${CLEANUP[@]}"' EXIT

CLOUD_INIT_DIR="$(mktemp -d)"; CLEANUP+=("$CLOUD_INIT_DIR")
RESULT_DIR="$(mktemp -d)";     CLEANUP+=("$RESULT_DIR")

# QEMU shares the host rootkat tree at /root/rootkat via virtio-9p, and
# a result tmpdir at /mnt/result. cloud-init writes a runtest script + a
# systemd one-shot service + a GRUB drop-in that adds `bpf` to lsm=. On
# first boot, runcmd checks whether bpf is already in /sys/kernel/security/lsm:
#   - if yes: run the test directly, write rc, poweroff.
#   - if no:  update-grub + enable rootkat-test.service + reboot. On the
#            second boot the kernel has lsm=...,bpf and the systemd unit
#            runs the test after multi-user.target. Adds ~30s on first run.
cat > "$CLOUD_INIT_DIR/user-data" <<EOF
#cloud-config
network: {config: disabled}
write_files:
  - path: /etc/default/grub.d/99-bpf-lsm.cfg
    content: |
      GRUB_CMDLINE_LINUX="\$GRUB_CMDLINE_LINUX lsm=lockdown,capability,landlock,yama,apparmor,bpf"
  - path: /usr/local/bin/rootkat-runtest.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -u
      mkdir -p /root/rootkat /mnt/result
      mount -t 9p -o trans=virtio,version=9p2000.L rootkat /root/rootkat 2>/dev/null || true
      mount -t 9p -o trans=virtio,version=9p2000.L result /mnt/result 2>/dev/null || true
      bash /root/rootkat/$TEST_SCRIPT > /mnt/result/log 2>&1
      echo \$? > /mnt/result/rc
      poweroff
  - path: /etc/systemd/system/rootkat-test.service
    content: |
      [Unit]
      Description=rootkat test runner
      After=multi-user.target
      Wants=multi-user.target
      [Service]
      Type=oneshot
      ExecStart=/usr/local/bin/rootkat-runtest.sh
      [Install]
      WantedBy=multi-user.target
runcmd:
  - |
    if grep -qw bpf /sys/kernel/security/lsm; then
        /usr/local/bin/rootkat-runtest.sh
    else
        update-grub
        systemctl enable rootkat-test.service
        reboot
    fi
EOF
echo "instance-id: rootkat-test" > "$CLOUD_INIT_DIR/meta-data"

cloud-localds "$CLOUD_INIT_DIR/seed.img" \
    "$CLOUD_INIT_DIR/user-data" "$CLOUD_INIT_DIR/meta-data"

# Wrap QEMU in `timeout` so a hung VM fails the test instead of running
# until the CI job's own timeout. `|| true` because QEMU's own exit code
# is not what we care about — the rc file inside the VM is.
if [ "$ARCH" = "arm64" ]; then
    timeout "$TIMEOUT_SECS" qemu-system-aarch64 \
        -enable-kvm -cpu host -m 2048 -smp 2 \
        -M virt,gic-version=3 \
        -bios /usr/share/qemu-efi-aarch64/QEMU_EFI.bin \
        -drive if=virtio,file="$IMG",format=qcow2,snapshot=on \
        -drive if=virtio,file="$CLOUD_INIT_DIR/seed.img",format=raw \
        -fsdev local,id=rootkat,path="$ROOT",security_model=none \
        -device virtio-9p-pci,fsdev=rootkat,mount_tag=rootkat \
        -fsdev local,id=result,path="$RESULT_DIR",security_model=none \
        -device virtio-9p-pci,fsdev=result,mount_tag=result \
        -nographic -serial mon:stdio \
        || true
else
    timeout "$TIMEOUT_SECS" qemu-system-x86_64 \
        -enable-kvm -cpu host -m 2048 -smp 2 \
        -drive if=virtio,file="$IMG",format=qcow2,snapshot=on \
        -drive if=virtio,file="$CLOUD_INIT_DIR/seed.img",format=raw \
        -fsdev local,id=rootkat,path="$ROOT",security_model=none \
        -device virtio-9p-pci,fsdev=rootkat,mount_tag=rootkat \
        -fsdev local,id=result,path="$RESULT_DIR",security_model=none \
        -device virtio-9p-pci,fsdev=result,mount_tag=result \
        -nographic -serial mon:stdio \
        || true
fi

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
