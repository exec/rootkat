# Helper binaries for the QEMU test harness. Built inside the rootkat-build
# container; produces amd64 ELF binaries the VM can run directly.
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

CFLAGS ?= -O2 -Wall -Wextra -static

# bpf_lister links libbpf (dynamically — static libbpf needs libelf+zlib
# bundled which is brittle across glibc versions; the cloud image ships
# libbpf at runtime).
PKGCFG       ?= pkg-config
LIBBPF_CFLAGS := $(shell $(PKGCFG) --cflags libbpf)
LIBBPF_LIBS   := $(shell $(PKGCFG) --libs libbpf)

HELPERS := qemu/privesc_helper qemu/hide_helper qemu/net_helper qemu/unix_helper qemu/bpf_lister

all: $(HELPERS)

qemu/privesc_helper: qemu/privesc_helper.c
	$(CC) $(CFLAGS) $< -o $@

qemu/hide_helper: qemu/hide_helper.c
	$(CC) $(CFLAGS) $< -o $@

qemu/net_helper: qemu/net_helper.c
	$(CC) $(CFLAGS) $< -o $@

qemu/unix_helper: qemu/unix_helper.c
	$(CC) $(CFLAGS) $< -o $@

qemu/bpf_lister: qemu/bpf_lister.c
	$(CC) -O2 -Wall -Wextra $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f $(HELPERS)
