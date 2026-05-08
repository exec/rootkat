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
  one hook covers v4 and v6 ss queries. Note: `inet_diag` is built as
  a module on Ubuntu (`CONFIG_INET_DIAG=m`), so we call
  `request_module("inet_diag")` from our install path to trigger
  autoload before resolving the symbol.

UDP /proc/net/udp{,6} is also covered (separate hook pair on
`udp{4,6}_seq_show`, sharing the same hidden_ports list). Unix sockets
remain out of scope. The UDP netlink path (ss -ulnp via NETLINK_SOCK_DIAG
with IPPROTO_UDP) is not yet hooked; v3 milestone. Only local-port
matching is implemented; remote-port-only filtering would need a
separate code path.

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

### AF_UNIX socket path hiding

Two hooks share one substring registry (default `.rootkat`):

- `unix_seq_show` (in vmlinux): the per-row builder for
  `/proc/net/unix`. When the iterator visits a socket whose bound path
  contains a registered substring, the replacement returns 0 without
  writing the row — `lsof -U`, any `/proc` walker, and legacy socket
  inventories skip the entry.
- `sk_diag_fill` in the `unix_diag` module: the per-socket builder
  for the AF_UNIX `NETLINK_SOCK_DIAG` dump path used by `ss -lx`.
  Same skip pattern — return 0 without writing. The symbol is
  `static` in `net/unix/diag.c` and its name collides with
  identically-named statics in `inet_diag` and `raw_diag`, so it's
  resolved via `rootkat_lookup_in_module("sk_diag_fill", "unix_diag")`
  (module-scoped walk over `kallsyms_on_each_symbol` filtered by
  `__module_address(addr)->name`). `request_module("unix_diag")` is
  triggered at install time because Ubuntu builds `CONFIG_UNIX_DIAG=m`.

Substring (not prefix or exact match) so a process can pick any path
containing the marker. The default `.rootkat` substring is added at
module init.

- **Coverage:** A unix_helper bound at `/tmp/.rootkat-secret.sock`
  is invisible to both `cat /proc/net/unix` and `ss -lx`; the same
  helper bound at `/tmp/normal.sock` is visible to both. Direct
  `connect(2)` to the hidden path still succeeds — we hide from
  enumeration only.
- **Detection:**
  - For filesystem-backed unix sockets, the bind path always leaves
    a node on disk. The mismatch between `ls /tmp/.rootkat-*.sock`
    (file present) and the absence in BOTH `/proc/net/unix` and
    `ss -lx` is a strong signal.
  - For abstract sockets, the bound name only lives in
    `/proc/net/unix` and the netlink dump — both hidden, so a
    defender cannot enumerate them without ftrace introspection.
  - ftrace artifacts on `unix_seq_show` and the unix_diag-scoped
    `sk_diag_fill` are observable via
    `/sys/kernel/debug/tracing/enabled_functions`.
  - `bind(2)` from another process to the same filesystem path
    returns EADDRINUSE.

### io_uring covert-channel control surface

- `io_issue_sqe` (the per-opcode dispatcher in `io_uring/io_uring.c`) is
  hooked. When it sees an `IORING_OP_NOP` SQE whose `user_data` carries
  the rootkat magic prefix in its top 32 bits (`0x726b6174` = "rkat"),
  it decodes an action code from bits [31:24] and an arg from bits
  [23:0], performs the corresponding side-effect (privesc /
  hide-pid / hide-port), then falls through to the original NOP
  handler so the caller sees a normal successful completion.
- The static `io_issue_sqe` is in vmlinux, resolved via the
  module-scoped lookup primitive (`module_name = NULL` → walk vmlinux
  kallsyms).
- **Why this matters:** the same operations are also reachable via the
  `kill(_, 64/63/62)` magic-signal path (see `hook_sys_kill`). A
  syscall-level audit ruleset (auditd watching `kill`, sysdig with the
  default rule set, eBPF probes on `sys_enter_kill`) catches the kill
  path. It does NOT catch the io_uring path — the operator only invokes
  `io_uring_enter`, which is legitimate enough that most rulesets don't
  flag every call. This pair is a deliberate teaching artifact: the same
  effect, two surfaces, only one of them visible to syscall monitoring.
- **Detection:**
  - ftrace artifact on `io_issue_sqe` is observable in
    `/sys/kernel/debug/tracing/enabled_functions`. This is the most
    reliable detection — same as every other rootkat hook.
  - The kernel's own io_uring tracepoints (`io_uring:io_uring_submit_req`
    with `req->cqe.user_data` visible) record every SQE. A defender
    enabling those would see SQEs with the suspicious magic prefix.
    The default tracepoint config doesn't capture this; enabling it
    is the first counter.
  - `io_uring_register(IORING_REGISTER_RESTRICTIONS)` lets a process
    pre-restrict its own ring's allowed opcodes/sqe-flags. A defender
    can't apply that to other processes' rings, but defensive userspace
    can lock its own ring down.
  - The hooked dispatcher applies to ALL io_uring SQEs in the system,
    not just the operator's. Hot io_uring workloads (databases,
    QUIC servers) take a small per-SQE overhead (`(opcode==NOP) &&
    (user_data >> 32 == magic)` — two comparisons). Performance
    counters on `io_issue_sqe` would show this if the defender
    looks for it.

### Netfilter covert-channel control surface

- A netfilter hook at `NF_INET_PRE_ROUTING` (priority `NF_IP_PRI_FIRST`)
  inspects every inbound IPv4 UDP packet. If the first 16 payload bytes
  are the magic frame (`"rootkat\0"` + 1-byte action + 3-byte
  reserved + 4-byte big-endian arg), it decodes and runs the action
  (hide-pid or hide-port), then returns `NF_DROP` so the packet never
  reaches any local socket.
- **No listening socket required.** The host doesn't need to `bind()`
  anything: the hook fires before routing, before socket dispatch.
  `lsof -i UDP` and `/proc/net/udp` show nothing listening; the rootkit
  still receives commands.
- **Why this matters:** completes the local/IPC/remote channel triptych
  along with the kill magic-signal path and the io_uring NOP-SQE path.
  The same `magic_actions.c` registry-mutator logic is reachable three
  ways, only one of which (`kill`) is visible to syscall-level audit.
  The netfilter path is visible only to defenders specifically watching
  the kernel's netfilter hook list.
- **Privesc deliberately not exposed on this channel** — privesc requires
  a target task context, and an inbound packet has no notion of "the
  caller". The natural absolute-target form (`privesc PID X to root`)
  would require modifying another task's creds from outside its run
  context, which is delicate. Caller-context privesc is reachable via
  the kill / io_uring channels.
- **Detection:**
  - `cat /proc/net/netfilter/nf_log` shows registered hooks per family.
    Modern kernels also expose hook info via `nft list hooks` (nftables)
    or `iptables-save` (legacy iptables) — neither shows our raw
    `nf_register_net_hook` registration directly, but the kernel's
    internal hook chain at `NF_INET_PRE_ROUTING` includes our function
    address. A defender enumerating netfilter hooks via the
    `xtables-monitor` style or by walking `init_net.nf.hooks_ipv4`
    sees an unfamiliar function pointer.
  - ftrace artifact on the hook itself (`rootkat_nf_pre_routing`) is
    NOT enumerable via `/sys/kernel/debug/tracing/enabled_functions`
    — that's only ftrace-instrumented hooks. We don't ftrace-hook this
    one; netfilter has its own hook table. Defenders need to walk that
    table, not the ftrace one.
  - `tcpdump -i lo -n udp` running on the host BEFORE rootkat loaded
    captures the magic packet. Once rootkat is loaded, the same `tcpdump`
    still sees the packet at the AF_PACKET tap (libpcap taps before
    netfilter), so a defender packet-capturing the host can spot the
    distinctive `"rootkat\0"` prefix in payloads.
  - The hook is in `init_net` (root network namespace) only. Packets
    from a different netns aren't seen — a defender running rootkat in
    a constrained namespace can box the channel.

### Audit log suppression

- `audit_log_start` is hooked. When called from a hidden PID's task
  context, returns NULL — the audit subsystem treats NULL as "skip
  event" (callers do `if (!ab) return;` and `audit_log_format` on NULL
  is a no-op). Standard kernel audit pipeline, kAudit, and userspace
  auditd do not see audit events generated by hidden processes.
- **Coverage:** any audit point that goes through `audit_log_start`.
  Specialized paths that bypass it (some SELinux AVC paths, audit's
  own internal self-audit) are still observed by defenders.
- **Detection:** running `auditctl -a always,exit -F arch=b64 -S openat
  -F pid=<HIDDEN>` and seeing zero events is itself suspicious if
  paired with `ps`-visible activity from the same PID. Cross-checking
  ftrace artifacts on `audit_log_start` via
  `/sys/kernel/debug/tracing/enabled_functions` is more reliable.
- **Not CI-asserted:** auditd setup in cloud-init is fragile and we
  deliberately don't bake it into the QEMU harness. The hook's
  behavior is verified manually against a live auditd.

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

### BPF program self-hide

- The sys_bpf hook intercepts `BPF_PROG_GET_NEXT_ID` and skips past any
  prog whose name (in `bpf_prog_aux->name`) matches the rootkat hidden
  string. `bpftool prog list`, `libbpf` enumerators, and the `bpf-iter`
  programs that go through the syscall path all see a contiguous-looking
  ID space minus our entry.
- The hook resolves `bpf_prog_by_id` and `bpf_prog_put` via kallsyms at
  install time (these are not exported symbols).
- Detection: a defender can read `/sys/kernel/btf/vmlinux` directly, or
  enumerate via `BPF_OBJ_GET_INFO_BY_FD` against an fd they obtained
  through other means (e.g., `/proc/self/fdinfo/<fd>` of a known loader
  process). The hook only filters `BPF_PROG_GET_NEXT_ID`.
- ftrace artifact on `__x64_sys_bpf` is observable in
  `/sys/kernel/debug/tracing/enabled_functions`.

### eBPF file hide via LSM

- `bpftool prog list` no longer shows the loaded program (BPF-program-
  hiding ships in this version, see above).
- Auditd records the BPF syscall at load time.
- The hooked LSM is observable via `bpftool perf list`.
- **Boot requirement:** the BPF LSM hook only fires when `bpf` is present in
  the kernel's boot-time `lsm=` list. Ubuntu 26.04's default cmdline does
  not include it. The QEMU test harness automates this by writing
  `/etc/default/grub.d/99-bpf-lsm.cfg`, running `update-grub`, and
  rebooting before the test runs (adds ~30s on first boot per test).
  Production deployers must do the equivalent themselves.
