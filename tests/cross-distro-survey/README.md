# Cross-distro survey

Operator tool — **not** part of the automated CI matrix. Brings up a
VM from a cloud image of $DISTRO on a Proxmox VE host, drives
cloud-init to install kernel headers + git + a build toolchain,
clones rootkat from GitHub, builds the LKM in-VM, runs `insmod` /
`rmmod`, and captures the results back to the operator's machine.

The point is to surface kernel-version-specific or distro-specific
issues that the CI matrix structurally can't see. CI tests Ubuntu
26.04 (kernel 7.0) and Ubuntu 24.04 LTS (kernel 6.8); a regression
in any kernel between those — or in any non-Ubuntu kernel build
config — slips through.

This was the tooling that surfaced the tail-call recursion bug fixed
in 13cfc86: rootkat soft-locked Debian 6.12 and Fedora 6.14 because
`return orig(...)` got sibling-call optimized into a JMP, defeating
the `within_module(parent_ip, THIS_MODULE)` recursion guard.

## Prereqs

A Proxmox VE host (tested with PVE 8 / Debian 13 / kernel 6.17).
Required packages are typically present on a stock PVE install:
`qm`, `qemu-server`, `python3`, `socat`. The operator runs the
script over SSH; the host needs passwordless sudo for the operator
account.

One-time PVE config: enable `snippets` content type on the storage
that holds the cloud-init userdata files (default `local`):

    sudo pvesm set local --content iso,import,backup,vztmpl,snippets

## Usage

    # Download a cloud image to /var/lib/vz/template/iso/ or wherever:
    curl -o /var/lib/vz/template/iso/ubuntu-24.04-cloud.img \
        https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img

    ./run.sh ubuntu24 /var/lib/vz/template/iso/ubuntu-24.04-cloud.img 9001

Args: `<distro-name> <image-path> [vmid]`. The distro name must
match a file in `distros/<name>.yaml` next to this script.

Env knobs:
- `KEEP=1` — leave the VM up after the run (debug)
- `STORAGE=<pool>` — VM disk storage pool (default `local-zfs`)
- `BRIDGE=<bridge>` — network bridge (default `vmbr0`)

Results land in `results/<distro>/`:
- `os`, `uname` — what booted
- `build.rc`, `build.log` — kernel module compile result
- `insmod.rc`, `insmod.log` — load result
- `rmmod.rc`, `rmmod.log` — unload result
- `dmesg.log` — last 50 dmesg lines after insmod
- `serial.log` — full kernel/systemd/cloud-init console
  (independent of guest-agent — captured even if the VM hangs)

## Adding a new distro

Drop a `distros/<name>.yaml` next to the others. Each yaml is a
cloud-init `#cloud-config` document that:

1. Installs `qemu-guest-agent` (so `qm guest exec` works for result
   capture) plus a build toolchain (`build-essential` /
   `kernel-devel` / `base-devel` etc.) and `git`.
2. Writes `/usr/local/bin/rootkat-survey-run` via `write_files`.
   The script:
   - clones rootkat from `https://github.com/exec/rootkat.git`
   - runs `make -C lkm ROOTKAT_I_UNDERSTAND=1`
   - `insmod rootkat.ko`, sleeps, captures `dmesg`, `rmmod`s
   - writes rcs/logs under `/tmp/rootkat-survey/`
   - touches `/tmp/rootkat-survey/done` as the completion marker
3. Has a `runcmd` that:
   - enables qemu-guest-agent
   - runs the survey script in the background (otherwise cloud-init
     blocks on it forever)

Note `/tmp/` not `/run/` — Fedora's SELinux context on `/run/`
denies access from the qemu-guest-agent's restricted domain even
when running as root. Fedora's userdata also includes a
`setenforce 0` step in `runcmd`.

For rolling-release distros (Arch), the cloud image's booted kernel
will lag behind whatever `<distro>-headers` packages currently
resolve to. The fix would be a `pacman -Syu` + reboot dance with a
systemd unit that fires the survey on second boot — not implemented
here. Arch's userdata builds anyway and demonstrates the failure
mode.

## 2026-05-08 baseline

| Distro            | Kernel              | build | insmod | rmmod | Notes |
|-------------------|---------------------|-------|--------|-------|-------|
| Ubuntu 24.04      | 6.8.0-106-generic   | ✅ 0  | ✅ 0   | ✅ 0  | clean |
| Debian 13 trixie  | 6.12.85+deb13-cloud | ✅ 0  | ✅ 0   | ✅ 0  | clean (post 13cfc86) |
| Fedora 42         | 6.14.0-63.fc42      | ✅ 0  | ✅ 0   | ✅ 0  | clean (post 13cfc86) |
| Arch Linux        | 7.0.3-arch1-1       | ❌    | n/a    | n/a   | rolling-release lag — pacman headers ahead of booted kernel |

Pre-fix, Debian and Fedora soft-locked at insmod with a recursive
`filldir64 → filldir64` trace (root cause: gcc sibling-call
optimization on the hook's `return orig(...)` defeating the ftrace
recursion guard).
