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

### Network port hiding (multi-surface)

The hidden_ports list is shared across three independent hooks that
together cover both detection paths and both families:

- `tcp4_seq_show` — `/proc/net/tcp`, used by `lsof -i`, /proc walkers,
  older `netstat` builds.
- `tcp6_seq_show` — same for `/proc/net/tcp6` (IPv6).
- `inet_sk_diag_fill` — the per-socket fill in the `NETLINK_SOCK_DIAG`
  dump path. `ss` uses this; hooking it returns 0 without writing to
  the dump skb, so the socket is silently skipped. Family-agnostic —
  one hook covers v4 and v6 ss queries.

UDP and Unix sockets remain out of scope; UDP would need
`udp4_seq_show` + `udp6_seq_show` hooks plus possibly a UDP-specific
diag fill. Only local-port matching is implemented; remote-port-only
filtering would need a separate code path.

**Detection notes:**
- The hidden socket still consumes a port — `bind(2)` from another
  process to the same port returns EADDRINUSE. That's the most reliable
  signal for a defender who suspects port hiding.
- `/proc/<pid>/fd/` for the listening process still shows the socket;
  walking processes and inspecting their fds (lsof's other code path,
  not the /proc/net path) reveals it.
- ftrace artifacts on `tcp4_seq_show`, `tcp6_seq_show`,
  `inet_sk_diag_fill` are visible in
  `/sys/kernel/debug/tracing/enabled_functions` for a privileged
  defender.

### Persistence via systemd

- `scripts/install.sh` writes a unit file at
  `/etc/systemd/system/rootkat-lkm.service` and a module copy at
  `/usr/local/lib/rootkat/rootkat.ko`. Both are visible to a defender
  walking `/etc/systemd/system/` or `/usr/local/lib/` *unless* further
  filesystem hiding is layered on (e.g. via the eBPF file-hide hook).
- `systemctl is-enabled rootkat-lkm.service` returns `enabled` — the
  systemd unit is enumerable via dbus / `systemctl list-unit-files`
  even when the LKM is hidden from `/proc/modules`.
- The `Description=` field of the unit file is the strongest static
  indicator and trivially renamable. Detection via behavioral analysis
  of the auto-load (e.g. an unrecognized module loaded before
  `multi-user.target`) is more robust than string-based hunts.

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
