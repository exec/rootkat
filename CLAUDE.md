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
./scripts/build.sh                       # build LKM + eBPF + Rust + helpers
BUILD_IMAGE_FORCE=1 ./scripts/build.sh   # force container rebuild (Dockerfile churn)
```

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
- **`rust/`** — hello-world Rust LKM. Builds against
  `linux-lib-rust-7.0.0-15-generic` + `rustc 1.93.1` from Ubuntu 26.04.
  Pattern is in place; no rootkit functionality yet.
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

## Current status (2026-05-07)

v0.6 — 14 features verified end-to-end on real Linux 7.0 in CI (audit
hook is code-only / not CI-asserted). 9/9 QEMU tests pass. 72 commits
on `main`.

Backlog: Unix-socket hiding (path-based), io_uring covert channel,
multi-kernel CI matrix, port real C component to Rust. See
`README.md` "What's NOT here yet" for the canonical list.
