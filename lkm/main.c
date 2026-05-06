// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "kallsyms.h"
#include "resolver.h"

#define ROOTKAT_TAG "rootkat: "

static int __init rootkat_init(void)
{
	static const char * const init_task_candidates[] = {
		"init_task", NULL,
	};
	const char *matched = NULL;
	unsigned long addr;
	int rc;

	pr_info(ROOTKAT_TAG "loading\n");

	rc = rootkat_kallsyms_init();
	if (rc) {
		pr_err(ROOTKAT_TAG "kallsyms init failed: %d\n", rc);
		return rc;
	}

	addr = rootkat_resolve(init_task_candidates, &matched);
	if (!addr) {
		pr_err(ROOTKAT_TAG "init_task resolution failed\n");
		return -ENOENT;
	}
	pr_info(ROOTKAT_TAG "init_task (%s) @ %lx\n", matched, addr);

	pr_info(ROOTKAT_TAG "loaded\n");
	return 0;
}

static void __exit rootkat_exit(void)
{
	pr_info(ROOTKAT_TAG "unloaded\n");
}

module_init(rootkat_init);
module_exit(rootkat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rootkat");
MODULE_DESCRIPTION("Educational LKM rootkit skeleton");
MODULE_VERSION("0.0.1");
