# Refuse to build without explicit acknowledgement.
ifndef ROOTKAT_I_UNDERSTAND
$(error Set ROOTKAT_I_UNDERSTAND=1 to build. See README.md)
endif

obj-m += rootkat.o
rootkat-y := main.o kallsyms.o resolver.o ftrace_hook.o \
             hidden_pids.o hidden_ports.o \
             hook_m_show.o hook_sys_kill.o hook_filldir64.o hook_tcp4_seq_show.o

# Inside the build container, $(uname -r) returns the host kernel which has
# no headers tree. Resolve KDIR from the headers package layout instead.
KDIR ?= /lib/modules/$(shell ls /lib/modules | head -n1)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
