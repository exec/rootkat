# rootkat

An educational, open-source Linux 7.0+ rootkit. The goal is to teach how modern
kernel-mode stealth techniques actually work on contemporary kernels with CFI,
FineIBT, lockdown, BTF/CO-RE, and BPF LSM — and to ship the matching detection
documentation alongside.

## Status

v0.2 — six rootkit features verified end-to-end against Linux 7.0 in CI:

| Feature                     | Mechanism                                     | Trigger                       |
|-----------------------------|-----------------------------------------------|-------------------------------|
| Self-hide from `/proc/modules` | ftrace hook on `m_show`                    | Automatic on load             |
| Self-hide from `/sys/module/`  | ftrace hook on `filldir64`                 | Automatic on load             |
| File hide                   | CO-RE eBPF on `lsm/file_open`                | `loader <name>`               |
| Privesc to root             | ftrace hook on `__x64_sys_kill`              | `kill(0, 64)`                 |
| Process hide                | ftrace hook on `filldir64`                   | `kill(0, 63)` from the target |
| TCP port hide (v4 + v6)     | ftrace hooks on `tcp4_seq_show` / `tcp6_seq_show` | `kill(<port>, 62)`     |

All techniques are documented in `docs/threat-model.md` with their detection
artifacts. The matching test for each lives in `tests/qemu/test_*.sh` and runs
inside a real kernel-7.0 QEMU VM in CI.

## Design

- **LKM (C)** — ftrace-based hooks, kprobe-bootstrapped `kallsyms_lookup_name`,
  multi-candidate symbol resolver for kernel-version drift. Does the things eBPF
  structurally cannot: kernel-text rewriting, self-hiding, syscall return-value
  modification.
- **eBPF (CO-RE)** — LSM hooks for portable, version-survives stealth. Today:
  one program (file hide). v2 will add: BPF program self-hide, netlink/sock_diag
  rewriting (so `ss` is fooled too).
- **Userland loader (libbpf)** — loads and attaches the eBPF program; survives
  rebuilds across kernel versions via CO-RE relocations.
- **QEMU test harness** — drives a kernel-7.0 cloud image with cloud-init, runs
  each test inside the VM, propagates pass/fail. Auto-rewrites GRUB to put
  `bpf` in the LSM list before the file-hide test (Ubuntu 26.04's default
  cmdline omits it).

## Building

All builds run in a Docker container (works on macOS / non-Linux hosts):

    ./scripts/build.sh

Requires Docker + buildx. Colima users: `brew install docker-buildx` once.
The first invocation builds the container (~2 min); subsequent runs reuse it.
Force a rebuild with `BUILD_IMAGE_FORCE=1 ./scripts/build.sh`.

## Testing

The test harness needs KVM + cloud-localds + qemu-system-x86_64; CI on
GitHub Actions has all of them. Locally on Linux:

    ./tests/qemu/run.sh tests/qemu/test_self_hide.sh
    ./tests/qemu/run.sh tests/qemu/test_file_hide.sh
    ./tests/qemu/run.sh tests/qemu/test_privesc.sh
    ./tests/qemu/run.sh tests/qemu/test_process_hide.sh
    ./tests/qemu/run.sh tests/qemu/test_network_hide.sh

On macOS the QEMU step can't run locally (no KVM); push and let CI exercise it.

## Persistence

Use `scripts/install.sh` (run as root on the target) to install rootkat as a
systemd service that auto-loads on every boot. `scripts/uninstall.sh` reverses
it. `tests/qemu/test_persistence.sh` exercises the full install → reboot →
verify → uninstall cycle inside QEMU.

## Threat model & detection

See `docs/threat-model.md`. Every stealth technique here ships with a matching
detection note — that's a deliverable, not an afterthought. A defender who
reads the threat model can build a detector for rootkat in an afternoon.

## What's NOT here yet (v2 backlog)

- BPF program self-hide (visible to `bpftool prog list`)
- Netlink/sock_diag rewriting (so `ss` is also fooled, not just /proc/net/tcp)
- Audit log suppression
- UDP / Unix-socket hiding
- io_uring covert channel
- Rust LKM component
- Multi-kernel CI matrix (linux-next bumps)
- C2 integration

## Educational use only

This project exists to teach kernel security. Loading rootkat on a system you
do not own is illegal in most jurisdictions. The Makefile requires
`ROOTKAT_I_UNDERSTAND=1` to build, and the project respects:

- Kernel lockdown LSM (`integrity` / `confidentiality` modes refuse loading)
- Module signature enforcement (`module.sig_enforce=1` refuses unsigned)
- `kernel.unprivileged_bpf_disabled=2` (eBPF needs CAP_BPF)

If you're using this to learn, the most valuable thing you can do after reading
the code is read `docs/threat-model.md` and then try to build a detector.
