#!/usr/bin/env bash
# Bring up a VM from a cloud image, run the rootkat smoke build+load
# inside via cloud-init, capture results, destroy. PVE qm + cloud-init
# + qemu-guest-agent + serial tap.
#
# Usage:
#   ./run.sh <distro> <image> [vmid]
#
# Args:
#   distro: matches a distros/<name>.yaml file next to this script
#   image:  path to a cloud-image qcow2/raw on the PVE host
#   vmid:   VM id to use (default 9001)
#
# Env:
#   KEEP=1    keep the VM up on completion (debug); default destroys it
#   STORAGE   PVE storage pool for the VM disk (default: local-zfs)
#   BRIDGE    network bridge (default: vmbr0)
#   SNIPPETS  PVE snippets dir (default: /var/lib/vz/snippets)
#
# Prereqs on the PVE host:
#   - The `local` storage (or whichever holds your snippets) must allow
#     `snippets` content type. Enable once with:
#       sudo pvesm set local --content iso,import,backup,vztmpl,snippets
#   - python3, socat in PATH (both ship by default on PVE).
set -euo pipefail

DISTRO="${1:?usage: run.sh <distro> <image> [vmid]}"
IMAGE="${2:?usage: run.sh <distro> <image> [vmid]}"
VMID="${3:-9001}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USERDATA="$HERE/distros/$DISTRO.yaml"
RESULTS="$HERE/results/$DISTRO"
KEEP="${KEEP:-0}"
STORAGE="${STORAGE:-local-zfs}"
BRIDGE="${BRIDGE:-vmbr0}"
SNIPPETS="${SNIPPETS:-/var/lib/vz/snippets}"

[ -r "$USERDATA" ] || { echo "no userdata: $USERDATA" >&2; exit 2; }
[ -r "$IMAGE" ]    || { echo "no image: $IMAGE"       >&2; exit 2; }

mkdir -p "$RESULTS"
QM="sudo /usr/sbin/qm"

# Stomp any leftover VM (e.g. previous failed run with KEEP=0 racing).
if $QM status "$VMID" >/dev/null 2>&1; then
  $QM stop "$VMID" >/dev/null 2>&1 || true
  $QM destroy "$VMID" --purge >/dev/null 2>&1 || true
fi

sudo install -m 0644 "$USERDATA" "$SNIPPETS/userdata-$VMID.yaml"

echo "[$DISTRO] creating VM $VMID..."
$QM create "$VMID" \
  --name "rootkat-survey-$DISTRO" \
  --memory 2048 --cores 2 \
  --net0 "virtio,bridge=$BRIDGE" \
  --scsihw virtio-scsi-single \
  --ostype l26 \
  --agent enabled=1 \
  --serial0 socket --vga serial0 >/dev/null

echo "[$DISTRO] importing disk..."
$QM importdisk "$VMID" "$IMAGE" "$STORAGE" --format raw >/dev/null 2>&1

# `cicustom` references a snippet path relative to a PVE storage. The
# default `local` storage is at /var/lib/vz, so we use "local:snippets/<file>".
SNIP_STORAGE_PREFIX="${SNIPPETS_STORAGE_PREFIX:-local:snippets}"
$QM set "$VMID" \
  --scsi0 "$STORAGE:vm-$VMID-disk-0,discard=on,iothread=1" \
  --boot order=scsi0 \
  --ide2 "$STORAGE:cloudinit" \
  --cicustom "user=$SNIP_STORAGE_PREFIX/userdata-$VMID.yaml" \
  --ipconfig0 ip=dhcp >/dev/null

$QM resize "$VMID" scsi0 +5G >/dev/null

echo "[$DISTRO] starting VM..."
$QM start "$VMID"

# Tap the serial socket asynchronously (-u read-only so the VM's stdin
# stays untouched). PID is tracked so we can kill the tap on exit.
truncate -s 0 "$RESULTS/serial.log"
sudo socat -u "UNIX-CONNECT:/var/run/qemu-server/$VMID.serial0" \
                 "OPEN:$RESULTS/serial.log,creat,append" >/dev/null 2>&1 &
SOCAT_PID=$!
echo "[$DISTRO] serial tap pid=$SOCAT_PID -> $RESULTS/serial.log"

cleanup_socat() { sudo kill $SOCAT_PID 2>/dev/null || true; }
trap cleanup_socat EXIT

# Wait for the qemu-guest-agent to come up. Cloud-init installs and
# enables it as one of the first packages; up to 5 minutes.
for i in $(seq 1 60); do
  if $QM agent "$VMID" ping >/dev/null 2>&1; then
    echo "[$DISTRO] guest agent up after $((i*5))s"; break
  fi; sleep 5
done

# Wait for the survey script (rootkat-survey-run, see distros/*.yaml) to
# touch /tmp/rootkat-survey/done. Up to 12 minutes — fresh apt/dnf updates
# on cold images can take a while.
DONE=0
for i in $(seq 1 144); do
  if $QM guest exec "$VMID" -- /usr/bin/test -f /tmp/rootkat-survey/done 2>/dev/null \
       | grep -q "\"exitcode\" : 0"; then
    DONE=1
    echo "[$DISTRO] marker present after $((i*5))s post-agent"
    break
  fi
  sleep 5
done

if [ "$DONE" = 0 ]; then
  echo "[$DISTRO] WARN: marker timeout — see $RESULTS/serial.log for VM console output"
fi

# Fetch artifacts via guest exec (best effort — files may be missing if
# the script hung mid-flight).
fetch() {
  local f="$1"
  $QM guest exec "$VMID" -- /usr/bin/cat "/tmp/rootkat-survey/$f" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get(\"out-data\",\"\"),end=\"\")"
}
for f in os uname build.rc build.log insmod.rc insmod.log dmesg.log rmmod.rc rmmod.log; do
  fetch "$f" > "$RESULTS/$f" 2>/dev/null || true
done

if [ "$KEEP" = "1" ] || [ "$DONE" = 0 ]; then
  echo "[$DISTRO] keeping VM $VMID (KEEP=$KEEP DONE=$DONE) — destroy with: sudo qm stop $VMID && sudo qm destroy $VMID --purge"
else
  echo "[$DISTRO] tearing down VM..."
  $QM stop "$VMID" >/dev/null 2>&1 || true
  $QM destroy "$VMID" --purge >/dev/null 2>&1 || true
fi

echo "[$DISTRO] results in $RESULTS"
ls -la "$RESULTS"
