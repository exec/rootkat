ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

CLANG    ?= clang
BPFTOOL  ?= bpftool
PKGCFG   ?= pkg-config

# Use the build container's vmlinux BTF; CO-RE relocations make the
# resulting .bpf.o portable across kernel versions at load time.
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

BPF_CFLAGS := -O2 -g -target bpf \
              -D__TARGET_ARCH_x86 \
              -I.

LIBBPF_CFLAGS := $(shell $(PKGCFG) --cflags libbpf)
LIBBPF_LIBS   := $(shell $(PKGCFG) --libs libbpf)

all: vmlinux.h hide_file.bpf.o loader

vmlinux.h:
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@

%.bpf.o: %.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

loader: loader.c
	$(CC) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS) -lelf -lz

clean:
	rm -f vmlinux.h *.bpf.o loader
