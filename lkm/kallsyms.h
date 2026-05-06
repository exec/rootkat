/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_KALLSYMS_H
#define ROOTKAT_KALLSYMS_H

/*
 * Bootstraps kallsyms_lookup_name via a temporary kprobe. Call once on
 * module init before any other symbol resolution. Returns 0 on success.
 */
int rootkat_kallsyms_init(void);

/* Resolve a kernel symbol by name. Returns 0 if not found. */
unsigned long rootkat_lookup_name(const char *name);

#endif
