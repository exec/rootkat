# Helper binaries for the QEMU test harness. Built inside the rootkat-build
# container; produces amd64 ELF binaries the VM can run directly.
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

CFLAGS ?= -O2 -Wall -Wextra -static

HELPERS := qemu/privesc_helper

all: $(HELPERS)

qemu/privesc_helper: qemu/privesc_helper.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(HELPERS)
