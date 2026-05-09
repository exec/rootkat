# rootkat — project notes for Claude

Educational, open-source Linux 7.0+ rootkit. LKM (C) + CO-RE eBPF + a Rust
hello-world LKM. Detection documentation in `docs/threat-model.md` is a
first-class deliverable, not an afterthought.

Repo: https://github.com/exec/rootkat

## Hard rules

- **Open-source educational framing is non-negotiable.** Don't suggest
  weaponization, EDR-bypass tuning, or detection-evasion-for-its-own-sake.
  Every stealth feature ships with detection notes alongside it in
  `docs/threat-model.md` — that's a deliverable.
- **Never build without `ROOTKAT_I_UNDERSTAND=1`.** The Makefile errors out
  without it. This is intentional friction, leave it in.
- **Never weaken hardening guards.** rootkat respects lockdown LSM,
  `module.sig_enforce=1`, `kernel.unprivileged_bpf_disabled=2`. Don't add
  bypasses for these.

## Build / test invocations

All builds run in a Docker container (works on macOS / non-Linux hosts):

```
./scripts/build.sh                              # default: Ubuntu 26.04 / kernel 7.0
UBUNTU_VERSION=24.04 ./scripts/build.sh         # Ubuntu 24.04 LTS / kernel 6.x
BUILD_IMAGE_FORCE=1 ./scripts/build.sh          # force container rebuild
```

The container image is tagged per Ubuntu version
(`rootkat-build:ubuntu-${UBUNTU_VERSION}`) so the matrix entries don't
stomp each other. Kernel headers come from `linux-headers-generic` for
that release; the Dockerfile's Rust splice only fires when a matching
`linux-lib-rust-*-generic` package exists (currently 26.04).

QEMU tests (Linux host w/ KVM, or in CI):

```
./tests/qemu/run.sh tests/qemu/test_self_hide.sh
./tests/qemu/run.sh tests/qemu/test_file_hide.sh
./tests/qemu/run.sh tests/qemu/test_privesc.sh
./tests/qemu/run.sh tests/qemu/test_process_hide.sh
./tests/qemu/run.sh tests/qemu/test_network_hide.sh
./tests/qemu/run.sh tests/qemu/test_load_unload.sh
./tests/qemu/run.sh tests/qemu/test_persistence.sh
./tests/qemu/run.sh tests/qemu/test_bpf_hide.sh
./tests/qemu/run.sh tests/qemu/test_rust_module.sh
```

On macOS the QEMU layer can't run locally (no KVM). Push and let GitHub
Actions exercise it: `gh run watch` to follow.

CI lives at `.github/workflows/ci.yml`. Runs on `ubuntu-24.04` (the
`ubuntu-26.04` runner label is not yet provisioned). The kernel-7.0
testing happens in QEMU + a Docker container, so the host runner OS
doesn't matter much. There's a udev step that makes `/dev/kvm` 0666 so
the build user can use it.

## Architecture cheat sheet

- **`lkm/`** — C kernel module. ftrace IPMODIFY hooks, kprobe-bootstrapped
  `kallsyms_lookup_name`, multi-candidate symbol resolver for kernel
  rename drift. Composition lives in `main.c`'s init/exit.
- **`ebpf/`** — CO-RE eBPF program(s) + libbpf loader. Today: file hide
  via `lsm/file_open`. Needs `bpf` in the kernel's `lsm=` list — the
  test harness rewrites GRUB and reboots once on first run.
- **`rust/`** — `rootkat_rust_canary.ko`. Built against
  `linux-lib-rust-7.0.0-15-generic` + `rustc 1.93.1` from Ubuntu 26.04.
  Maintains `static AtomicU32` and exports `rootkat_canary_tick()` /
  `rootkat_canary_value()` to other modules. rootkat.ko declares both
  as `__attribute__((weak))` and calls tick() at init — graceful
  degradation when the Rust LKM isn't loaded (24.04 matrix entry).
- **`scripts/install.sh` / `uninstall.sh`** — systemd-based persistence.
- **`tests/qemu/`** — `run.sh` drives a kernel-7.0 cloud image with
  cloud-init, virtio-9p mounts the project tree, runs one
  `test_*.sh` per invocation. Test scripts are bash + small C helpers
  (e.g. `hide_helper`, `privesc_helper`, `net_helper`).
- **`docs/threat-model.md`** — detection notes per technique. Every new
  stealth feature must add a section here in the same commit.

### Hook anatomy (`lkm/`)

Every hook follows the same shape:

1. `lkm/hook_<name>.c` — defines a `static struct rootkat_hook` with
   a `candidates[]` array of possible target symbol names (kernel
   rename forward-compat), the replacement function, and slots for
   `original` + resolved `target`.
2. `<name>_install()` resolves via `rootkat_resolve()` and arms ftrace.
3. `<name>_remove()` is idempotent; it clears `target` after disarming.
4. The replacement uses `container_of` to find the hook struct and
   `within_module(parent_ip, THIS_MODULE)` as the recursion guard.
   Calls into the original via the saved `original` pointer when needed.
5. The corresponding header exposes only `_install` and `_remove`.

`main.c` calls installs in dependency order, with non-fatal hooks
(everything past `tcp6_seq_show`) using `pr_warn` and continuing on
failure. `exit` reverses the order — every successful install must
have a matching remove call.

### Magic-signal control surface (`hook_sys_kill.c`)

The `kill(2)` syscall is hijacked to give userspace control without
opening a new device or netlink socket. Bypass conditions live in
`lkm/hook_sys_kill.h`:

- `kill(_, 64)` → privesc caller to root (signal 64 = SIGRTMAX)
- `kill(_, 63)` → hide caller's PID
- `kill(<port>, 62)` → hide port from /proc/net/tcp{,6} + udp{,6} + ss

Choosing high real-time signals avoids stomping on common app signals.

### Hidden-state lists

- `lkm/hidden_pids.{c,h}` — fixed-size spinlock-protected array.
- `lkm/hidden_ports.{c,h}` — same shape, used by all four
  `*_seq_show` hooks + `inet_sk_diag_fill`.
- Adding a new hidden-thing-list: copy this pattern (don't try to
  generalize across types — the spinlock + array pattern is short
  and clear).

## Conventions / gotchas

- **Symbol resolution.** Never call `kallsyms_lookup_name` — it's
  unexported since 5.7. Use `rootkat_lookup_name()` (kprobe trick from
  `lkm/kallsyms.c`). For multi-name lookups (kernel rename drift),
  use `rootkat_resolve(candidates, n)` from `lkm/resolver.c`. The
  resolver logs all attempted candidates on miss — leave that.
- **`KDIR` in the build container.** `uname -r` returns the host
  kernel which has no headers tree. The Makefile uses
  `/lib/modules/$(shell ls /lib/modules | head -n1)/build` instead.
  Don't switch back.
- **Docker on macOS / Colima.** `scripts/build.sh` uses
  `docker buildx build --platform linux/amd64 --load`. Classic
  `docker build --platform` is silently ignored under Colima — keep
  buildx.
- **inet_diag is a module on Ubuntu** (`CONFIG_INET_DIAG=m`). The
  `inet_sk_diag_fill` install path calls `request_module("inet_diag")`
  to trigger autoload before resolving the symbol. Don't drop that.
- **`inet_sk_diag_fill` is family-agnostic.** One hook covers TCP+UDP
  and v4+v6 over NETLINK_SOCK_DIAG. Don't add per-family copies.
- **dmesg ring buffer.** Tests sometimes lose rootkat init logs to
  ring rotation. If you need to assert on a log line, `dmesg -c`
  before insmod and grep what's left after.
- **filldir64 hook does double duty.** It hides PIDs (from `hidden_pids`)
  AND any path component containing the literal "rootkat" (for
  `/sys/module/rootkat/` self-hide). If you add a new directory-
  enumeration hide condition, extend the predicate in
  `hook_filldir64.c` rather than installing another hook.
- **Test harness multi-boot.** qcow2 `snapshot=on` overlay persists
  across guest reboots within ONE QEMU invocation, discarded when
  QEMU exits. `test_persistence.sh` uses a marker file
  (`/var/lib/rootkat-test-installed`) + a runtest systemd unit that
  fires every boot to branch on first-boot vs post-reboot.
- **`rust/hello.rs` `module!` macro.** `authors:` is a plural list
  (`["rootkat"]`), not a singular string. The macro auto-defines
  `__LOG_PREFIX`. `rustc 1.93.1` matches kernel
  `CONFIG_RUSTC_VERSION=109301`.
- **CI mobile false-fail notifications.** The user has reported
  occasional spurious GitHub-mobile fail pings on CI runs that
  actually pass. When following CI status, check `gh run list` and
  `gh run view <id>` for ground truth — and watch in_progress runs
  too, not just `--limit 1`.
- **kallsyms suffix matches.** When resolving via
  `rootkat_lookup_in_module`, prefer EXACT names over `.suffix`
  variants (`.cold`, `.constprop.0`, `.isra.0`). The `.cold` copy is a
  relocated error-path stub at an unaligned offset; ftrace_set_filter_ip
  fails -EINVAL on it. The resolver in `lkm/kallsyms.c` walks to
  completion and only falls back to the suffixed match if no exact
  match exists.
- **Don't bypass the ftrace recursion guard.** The
  `within_module(parent_ip, THIS_MODULE)` check in
  `rootkat_ftrace_thunk` makes the `orig(...)` pass-through safe —
  when our replacement calls orig, parent_ip is in our module, the
  guard skips our replacement, the original function body runs. If
  you disable the guard, calling orig re-enters ftrace → your
  replacement → infinite loop. Learned this the hard way on the
  printk hook in 3143844: the persistence test hung the boot for
  420s. Reverted in 704bd4b — silence rootkat's own logs at compile
  time via `pr_debug` instead.
- **Tail-call optimization defeats the recursion guard too.**
  `return orig(...)` as the last statement of a hook lets gcc
  sibling-call optimize it into a JMP. The return address on the
  stack stays as the kernel-side caller, so when the JMP lands at
  the ftrace-patched function entry, parent_ip is in kernel core,
  not in `THIS_MODULE` — the guard fails to short-circuit and the
  replacement runs again, infinitely. Hit on Debian 6.12 / Fedora
  6.14 in the 2026-05-08 cross-distro survey on eqr; Ubuntu 6.8
  and 7.0 happen to dodge the optimization in CI. Compiler-enforced
  defense in `lkm/Makefile`: `ccflags-y += -fno-optimize-sibling-calls`.
  Don't remove that flag without a damn good reason.

## Design decisions to respect

- **ftrace IPMODIFY works on 7.0 with CFI/FineIBT.** This was
  empirically settled. A previous reviewer (Singularity) raised the
  concern; CI verified it works. Don't reopen unless CI starts
  failing on it.
- **Magic-signal control beats a custom device/netlink/sysfs node.**
  No new attack surface, no name to grep for. Keep it.
- **Multi-candidate resolver everywhere.** Even when a symbol seems
  stable, list 1-2 plausible alternates so a kernel rename doesn't
  silently break the hook.
- **Detection notes in `docs/threat-model.md` are mandatory.** Every
  new stealth feature lands with its detection section in the same
  commit (or the immediately following one).
- **No alcapwn (C2) integration in this repo.** That was deferred by
  the user. Don't pre-wire it.

## Working with the user

The user is a cybersecurity student building this as a public learning
project (prior project: alcapwn C2). They've explicitly opted into
subagent-driven development for big tasks. Default to:

- Spawn agent teams (per `~/CLAUDE.md`) when multiple parallel
  workstreams are independent. Single isolated subagent only when
  context compartmentalization is genuinely required.
- For a new rootkit feature: ftrace hook + multi-candidate resolver +
  matching `tests/qemu/test_*.sh` step + CI step + detection note in
  `docs/threat-model.md`. That's the full delivery shape.
- After CI is green for a feature, commit message format is
  `lkm: <feature> (<one-line mechanism>)` or `docs: <feature>
  shipped; ...`. Keep the README "Status" table and the project memory
  file (`~/.claude/projects/.../memory/project_rootkat.md`) in sync.
- Don't suggest "production deployment" or "weaponization" tweaks.
  The educational + open-source framing is the project's premise.

## Current status (2026-05-08)

v0.13 — 20 features (audit hook is code-only / not CI-asserted).
Multi-kernel CI matrix: 13/13 tests pass on 26.04/7.0; 12/13 on
24.04/6.x (Rust canary test skipped — KERNEL_RUST=disabled for that
matrix entry).

v0.13 closes the obvious self-detection gap: rootkat's own
`pr_info("rootkat: ...")` lines and the kernel's `"loading
out-of-tree module taints kernel"` warning are now filtered at
`vprintk_emit` before reaching the kernel ring buffer. Every
consumer (klogctl/dmesg, /dev/kmsg, kdb, netconsole) sees the
stripped log. One install-time pr_info ("rootkat: loading") fires
BEFORE the filter is armed and survives — accepted bootstrap cost.

The three-channel control surface story (v0.12) is complete:
kill(_, 62..64) (local syscall), IORING_OP_NOP magic user_data
(local IPC), and inbound UDP magic frame at NF_INET_PRE_ROUTING
(remote network). Same registry mutators reachable three ways.

v0.11 added the Rust canary LKM (rootkat_rust_canary) — an
AtomicU32 with two #[no_mangle] extern "C" functions exported via
EXPORT_SYMBOL_GPL stubs. rootkat.ko calls them weak-linked at init
so it gracefully degrades when the Rust LKM isn't loaded.

Two control surfaces with parity now: the kill(2) magic-signal hijack
and the io_uring covert channel (IORING_OP_NOP SQE with magic
`user_data`). Both go through `lkm/magic_actions.c` for the actual
side effects (privesc / hide-current-pid / hide-port) — a single
implementation, two delivery channels. The teaching artifact: an
audit ruleset that watches `kill` catches the first but not the second.

Module-scoped resolver primitive (`rootkat_lookup_in_module`, in
`lkm/kallsyms.c`) walks vmlinux via `kallsyms_on_each_symbol` (NULL
module_name) or a specific module via `module_kallsyms_on_each_symbol`.
Used to pin static-named symbols that collide across modules
(`sk_diag_fill` in unix_diag/inet_diag/raw_diag) and to resolve static
vmlinux symbols (`io_issue_sqe`).

Backlog: port real C components to Rust, alcapwn C2 integration
(deferred). See `README.md` "What's NOT here yet" for the canonical
list.
