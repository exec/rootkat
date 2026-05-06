# rootkat

An educational, open-source Linux 7.0+ rootkit. The goal is to teach how modern
kernel-mode stealth techniques actually work on contemporary kernels with CFI,
FineIBT, lockdown, and BTF/CO-RE — and to ship the matching detection
documentation alongside.

## Status

Skeleton phase. Architecture pinned, vertical slice in progress. See
`docs/superpowers/plans/` for the active plan.

## Design

- **LKM (C)** — small, ftrace-based, does only what eBPF cannot: self-hide,
  hide BPF programs from `bpftool prog list`, kernel-text rewriting.
- **eBPF (CO-RE)** — bulk of functionality (file/process/network hiding)
  using LSM hooks and tracepoints. Survives kernel upgrades by design.
- **Userland loader** — libbpf-based; loads and pins both components.
- **QEMU test harness** — every behavior is asserted against a real kernel.

## Building

All builds run in a Docker container (works on macOS / non-Linux hosts):

    ./scripts/build.sh

## Testing

    ./tests/qemu/run.sh tests/qemu/test_self_hide.sh

## Threat model & detection

See `docs/threat-model.md`. Every stealth technique in rootkat ships with a
matching detection note — that's a deliverable, not an afterthought.

## Educational use only

This project exists to teach kernel security. Loading rootkat on a system you
do not own is illegal in most jurisdictions. The Makefile requires
`ROOTKAT_I_UNDERSTAND=1` to build.
