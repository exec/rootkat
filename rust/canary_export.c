// SPDX-License-Identifier: GPL-2.0
/*
 * EXPORT_SYMBOL_GPL stubs for the Rust-defined `rootkat_canary_*`
 * functions. The Rust kernel API in 7.0 doesn't yet provide a stable
 * `#[export]` mechanism for cross-module symbol visibility, so we
 * forward-declare the Rust functions here in C and emit the __ksymtab
 * entries via the existing C macros. Both files end up in the same
 * .ko (rootkat_rust_canary.ko) thanks to kbuild's per-file source
 * detection — no separate module, no load-order surprises.
 */
#include <linux/module.h>
#include <linux/types.h>

extern u32 rootkat_canary_tick(void);
extern u32 rootkat_canary_value(void);

EXPORT_SYMBOL_GPL(rootkat_canary_tick);
EXPORT_SYMBOL_GPL(rootkat_canary_value);
