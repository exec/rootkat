# rootkat threat model & detection notes

## What rootkat is

An educational LKM + eBPF rootkit targeting Linux 7.0+. It demonstrates
modern stealth techniques and documents how each is detected.

## What rootkat is NOT

- Not designed to bypass any specific commercial EDR
- Not designed to evade incident responders in a live engagement
- Not a tool for unauthorized access

## Hardening rootkat respects (does NOT attempt to bypass)

- **Lockdown LSM in `confidentiality` or `integrity` mode** — module loading
  is restricted; rootkat cannot load. This is correct behavior, not a bug.
- **Secure Boot with kernel module signing enforced** — unsigned modules
  refused. Same as above.
- **Unprivileged user namespaces with `kernel.unprivileged_bpf_disabled=2`** —
  eBPF loader requires CAP_BPF/CAP_SYS_ADMIN.

## Detection per component

### LKM self-hide via ftrace on `m_show`

- ftrace hook is enumerable: `cat /sys/kernel/debug/tracing/enabled_functions`
  shows `m_show` as a hooked function.
- Comparing `lsmod` against `kldstat`-equivalent BPF iterators over the module
  list reveals the discrepancy.
- `/sys/module/<name>/` directory still exists if not also hidden.
- Module taint: `cat /proc/sys/kernel/tainted` flips the OOT_MODULE bit.

### Network port hiding via `tcp4_seq_show`

- The hook intercepts `/proc/net/tcp` reads (used by `lsof -i`, `cat
  /proc/net/tcp`, older `netstat` builds, /proc walkers).
- **Known bypass:** modern `ss` uses `NETLINK_SOCK_DIAG` (the
  `inet_diag` family) which doesn't go through `tcp4_seq_show` — `ss
  -tln` will still list a hidden port. Defenders running `ss` get a
  signal; defenders relying on `/proc/net/tcp` do not. v2 milestone:
  netlink-rewriting eBPF companion that also filters `inet_diag` dump
  responses (the VoidLink pattern).
- IPv6 (`tcp6_seq_show`), UDP, and Unix sockets are out of scope for v1.
- Only the local port is matched; remote-port-only filtering would need
  a separate code path.

### eBPF file hide via LSM

- `bpftool prog list` shows the loaded program (until BPF-program-hiding is
  added in a later milestone).
- Auditd records the BPF syscall at load time.
- The hooked LSM is observable via `bpftool perf list`.
- **Boot requirement:** the BPF LSM hook only fires when `bpf` is present in
  the kernel's boot-time `lsm=` list. Ubuntu 26.04's default cmdline does
  not include it. The QEMU test harness automates this by writing
  `/etc/default/grub.d/99-bpf-lsm.cfg`, running `update-grub`, and
  rebooting before the test runs (adds ~30s on first boot per test).
  Production deployers must do the equivalent themselves.
