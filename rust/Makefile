# Out-of-tree Rust LKM build. Requires linux-lib-rust-X-generic to be
# spliced into linux-headers-X-generic/rust (the build container's
# Dockerfile does this once at image build time).
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

KDIR ?= /lib/modules/$(shell ls /lib/modules | head -n1)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
