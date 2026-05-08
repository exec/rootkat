// SPDX-License-Identifier: GPL-2.0
//! Rust LKM that maintains kernel-side state and exports it to the C
//! module via cross-module symbols.
//!
//! Demonstrates a real bit of Rust kernel code beyond hello-world:
//! a static `AtomicU32` counter, two `extern "C"` functions exposed
//! to other modules (`rootkat_canary_tick` and `rootkat_canary_value`),
//! and pr_info on init/exit. The C module (rootkat.ko) declares both
//! functions as `__attribute__((weak))` and calls tick() at its init —
//! when this Rust module isn't loaded (e.g. on the Ubuntu 24.04 matrix
//! entry where KERNEL_RUST=disabled), the weak symbol stays NULL and
//! the C side gracefully skips the call.

use core::sync::atomic::{AtomicU32, Ordering};
use kernel::prelude::*;

module! {
	type: CanaryModule,
	name: "rootkat_rust_canary",
	authors: ["rootkat"],
	description: "rootkat: Rust LKM with cross-module state (educational)",
	license: "GPL",
}

static CANARY: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
pub extern "C" fn rootkat_canary_tick() -> u32 {
	let n = CANARY.fetch_add(1, Ordering::Relaxed) + 1;
	pr_info!("rootkat_rust_canary: tick #{}\n", n);
	n
}

#[no_mangle]
pub extern "C" fn rootkat_canary_value() -> u32 {
	CANARY.load(Ordering::Relaxed)
}

struct CanaryModule;

impl kernel::Module for CanaryModule {
	fn init(_module: &'static ThisModule) -> Result<Self> {
		pr_info!("rootkat_rust_canary: armed (counter=0)\n");
		Ok(CanaryModule)
	}
}

impl Drop for CanaryModule {
	fn drop(&mut self) {
		pr_info!(
			"rootkat_rust_canary: disarmed (final counter={})\n",
			CANARY.load(Ordering::Relaxed)
		);
	}
}
