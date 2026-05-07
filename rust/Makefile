# Out-of-tree Rust LKM build. Requires linux-lib-rust-X-generic to be
# spliced into linux-headers-X-generic/rust (the build container's
# Dockerfile does this when the matching lib-rust package exists).
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

KDIR ?= /lib/modules/$(shell ls /lib/modules | head -n1)/build
PWD  := $(shell pwd)

# Detect kernel-Rust support. $(KDIR)/rust/kernel.o is the compiled
# kernel-rust core — present only when lib-rust artifacts are spliced
# in (the Dockerfile does this when a matching lib-rust package
# exists). On kernels without lib-rust support (e.g. Ubuntu 24.04 LTS
# / 6.8) it's absent — we no-op so the rest of the build still works.
HAS_KERNEL_RUST := $(shell test -e $(KDIR)/rust/kernel.o && echo yes)

ifeq ($(HAS_KERNEL_RUST),yes)
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
else
all:
	@echo "rust/Makefile: no Rust kernel artifacts in $(KDIR)/rust — skipping Rust LKM build."
	@echo "(this is expected on kernels that don't ship a lib-rust package)"

clean:
	@:
endif
