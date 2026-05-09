<p align="center">
  <img src="rootkat.png" alt="rootkat" width="200">
</p>

An educational, open-source Linux 6.8+ rootkit. The goal is to teach how modern
kernel-mode stealth techniques actually work on contemporary kernels with CFI,
FineIBT, lockdown, BTF/CO-RE, and BPF LSM — and to ship the matching detection
documentation alongside.

## Status

v0.13 — rootkit features verified end-to-end against multiple kernels
in CI (matrix: Ubuntu 24.04 LTS / kernel 6.8 + Ubuntu 25.04 / kernel 6.14 + Ubuntu 25.10 / kernel 6.17 + Ubuntu 26.04 / kernel 7.0):

| Feature                     | Mechanism                                     | Trigger                       |
|-----------------------------|-----------------------------------------------|-------------------------------|
| Self-hide from `/proc/modules` | ftrace hook on `m_show`                    | Automatic on load             |
| Self-hide from `/sys/module/`  | ftrace hook on `filldir64`                 | Automatic on load             |
| File hide                   | CO-RE eBPF on `lsm/file_open`                | `loader <name>`               |
| Privesc to root             | ftrace hook on `__x64_sys_kill`              | `kill(0, 64)`                 |
| Process hide                | ftrace hook on `filldir64`                   | `kill(0, 63)` from the target |
| TCP port hide (v4 + v6)     | ftrace hooks on `tcp4_seq_show` / `tcp6_seq_show` | `kill(<port>, 62)`     |
| TCP port hide from `ss`     | ftrace hook on `inet_sk_diag_fill` (NETLINK_SOCK_DIAG path) | (same)        |
| UDP port hide (v4 + v6)     | ftrace hooks on `udp4_seq_show` / `udp6_seq_show` | (same)                 |
| BPF program self-hide       | ftrace hook on `__x64_sys_bpf` (skip BPF_PROG_GET_NEXT_ID by name) | automatic |
| Audit log suppression       | ftrace hook on `audit_log_start` (return NULL for hidden PIDs) | per hidden PID |
| AF_UNIX path hide (`/proc/net/unix`) | ftrace hook on `unix_seq_show`; substring-match against `.rootkat` (default) | automatic for matching paths |
| AF_UNIX path hide (`ss -lx`) | ftrace hook on `unix_diag`'s static `sk_diag_fill`, resolved via module-scoped kallsyms lookup | (same registry) |
| io_uring covert control channel | ftrace hook on `io_issue_sqe`; magic `user_data` on `IORING_OP_NOP` SQE → privesc / hide-pid / hide-port | submit SQE via `io_uring_enter` |
| Netfilter covert control channel | `nf_register_net_hook` at `NF_INET_PRE_ROUTING`; magic 16-byte UDP payload prefix → hide-pid / hide-port | send UDP datagram with magic frame to any port (no listener needed) |
| dmesg / printk self-hide | ftrace hook on `vprintk_emit`; vsnprintf + marker scan, drop on `"rootkat"` substring | automatic on load (filters before ring buffer) |
| Rust canary (cross-module) | Rust LKM with `AtomicU32` exports `rootkat_canary_tick`/`_value`; rootkat.ko calls them weak-linked at init | auto on load (kernel-7.0 matrix only) |

All techniques are documented in `docs/threat-model.md` with their detection
artifacts. The matching test for each lives in `tests/qemu/test_*.sh` and runs
inside a QEMU VM in CI across the supported kernel matrix.

## Design

- **LKM (C)** — ftrace-based hooks, kprobe-bootstrapped `kallsyms_lookup_name`,
  multi-candidate symbol resolver for kernel-version drift. Does the things eBPF
  structurally cannot: kernel-text rewriting, self-hiding, syscall return-value
  modification.
- **eBPF (CO-RE)** — LSM hooks for portable, version-survives stealth. Today:
  one program (file hide). BPF program self-hide and ss netlink/sock_diag
  filtering shipped in the LKM side (see the status table); the eBPF
  surface is intentionally narrow because most rootkit work needs the
  text-rewriting + recursion-guard story that ftrace gives us.
- **Userland loader (libbpf)** — loads and attaches the eBPF program; survives
  rebuilds across kernel versions via CO-RE relocations.
- **Rust LKM (`rust/`)** — `rootkat_rust_canary.ko`, built against
  Ubuntu 26.04's `linux-lib-rust-7.0.0-15-generic` package + `rustc 1.93.1`.
  Maintains a static `AtomicU32` and exports `rootkat_canary_tick()` /
  `rootkat_canary_value()` via `#[no_mangle] extern "C"` — rootkat.ko
  declares both as `__attribute__((weak))` and calls tick() at init.
  When the Rust LKM isn't loaded (24.04 matrix entry, KERNEL_RUST=disabled),
  the weak symbols stay NULL and the C side gracefully skips. Pattern
  for porting further components to Rust as the kernel-Rust API grows.
- **QEMU test harness** — drives Ubuntu cloud images with cloud-init, runs
  each test inside the VM, propagates pass/fail. Auto-rewrites GRUB to put
  `bpf` in the LSM list before the file-hide test (Ubuntu 26.04's default
  cmdline omits it).

## Building

All builds run in a Docker container (works on macOS / non-Linux hosts):

    ./scripts/build.sh                              # Ubuntu 26.04 / kernel 7.0 (default)
    UBUNTU_VERSION=24.04 ./scripts/build.sh         # Ubuntu 24.04 LTS / kernel 6.8
    UBUNTU_VERSION=25.04 ./scripts/build.sh         # Ubuntu 25.04 / kernel 6.14
    UBUNTU_VERSION=25.10 ./scripts/build.sh         # Ubuntu 25.10 / kernel 6.17

Requires Docker + buildx. Colima users: `brew install docker-buildx` once.
The first invocation builds the container per Ubuntu version (~2 min);
subsequent runs reuse the matching image. Force a rebuild with
`BUILD_IMAGE_FORCE=1 ./scripts/build.sh`.

**Multi-kernel matrix.** CI exercises the full suite against Ubuntu 24.04 (6.8),
25.04 (6.14), 25.10 (6.17), and 26.04 (7.0). The Rust
LKM is built only when the matching kernel ships a `linux-lib-rust-*`
package (currently 26.04 only); on kernels without it, `rust/Makefile`
no-ops and `test_rust_module.sh` skips itself cleanly.

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

- Further C→Rust ports (the canary in v0.11 is the first real bit of
  Rust functionality; future ports await broader kernel-Rust API
  stabilization, e.g. ftrace, kallsyms helpers, procfs)
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
