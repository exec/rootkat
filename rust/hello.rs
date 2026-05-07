// SPDX-License-Identifier: GPL-2.0
//! Hello-world Rust LKM for rootkat.
//!
//! Demonstrates that the project's build pipeline produces a loadable
//! Rust kernel module on Linux 7.0 (which graduated Rust to stable).
//! No rootkit functionality here — the C module owns all the hooks.
//! This module exists to prove the toolchain works and to set the
//! pattern for porting individual components to Rust in v0.5+.

use kernel::prelude::*;

module! {
	type: HelloModule,
	name: "rootkat_rust_hello",
	authors: ["rootkat"],
	description: "rootkat: Rust hello-world LKM (educational)",
	license: "GPL",
}

struct HelloModule;

impl kernel::Module for HelloModule {
	fn init(_module: &'static ThisModule) -> Result<Self> {
		pr_info!("hello from rust on linux 7.0\n");
		Ok(HelloModule)
	}
}

impl Drop for HelloModule {
	fn drop(&mut self) {
		pr_info!("goodbye\n");
	}
}
