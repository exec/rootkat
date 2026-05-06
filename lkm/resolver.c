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

	for (c = candidates; *c; c++) {
		addr = rootkat_lookup_name(*c);
		if (addr) {
			pr_info(TAG "resolved '%s' -> %lx\n", *c, addr);
			if (matched)
				*matched = *c;
			return addr;
		}
	}
	pr_warn(TAG "no candidate resolved (first was '%s')\n",
	        candidates[0] ? candidates[0] : "(empty)");
	return 0;
}
