// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

#define ROOTKAT_TAG "rootkat: "

static int __init rootkat_init(void)
{
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
