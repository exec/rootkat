// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "kallsyms.h"

#define ROOTKAT_TAG "rootkat: "

static int __init rootkat_init(void)
{
	unsigned long addr;
	int rc;

	pr_info(ROOTKAT_TAG "loading\n");

	rc = rootkat_kallsyms_init();
	if (rc) {
		pr_err(ROOTKAT_TAG "kallsyms init failed: %d\n", rc);
		return rc;
	}

	addr = rootkat_lookup_name("init_task");
	if (!addr) {
		pr_err(ROOTKAT_TAG "could not resolve init_task\n");
		return -ENOENT;
	}
	pr_info(ROOTKAT_TAG "init_task @ %lx\n", addr);

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
