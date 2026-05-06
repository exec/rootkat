/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_FTRACE_HOOK_H
#define ROOTKAT_FTRACE_HOOK_H

#include <linux/ftrace.h>

struct rootkat_hook {
	const char * const *candidates;  /* NULL-terminated symbol candidates */
	void *replacement;               /* called instead of target */
	void *original;                  /* set by install: call this to defer */
	unsigned long target;            /* resolved address */
	struct ftrace_ops ops;
};

int rootkat_hook_install(struct rootkat_hook *h);
void rootkat_hook_remove(struct rootkat_hook *h);

#endif
