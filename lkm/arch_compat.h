/* SPDX-License-Identifier: MIT */
/*
 * Arch-agnostic accessors for pt_regs fields used by rootkat hooks.
 *
 * Syscall args:
 *   x86_64: RDI=arg1, RSI=arg2, RDX=arg3
 *   arm64:  x0=arg1,  x1=arg2,  x2=arg3
 *
 * Instruction pointer (for ftrace IPMODIFY redirect):
 *   x86_64: ip
 *   arm64:  pc
 */
#pragma once
#include <linux/ptrace.h>

#if defined(CONFIG_X86_64)
# define SYSCALL_ARG1(regs)       ((regs)->di)
# define SYSCALL_ARG2(regs)       ((regs)->si)
# define SYSCALL_ARG3(regs)       ((regs)->dx)
# define PT_REGS_IP(regs)         ((regs)->ip)
#elif defined(CONFIG_ARM64)
# define SYSCALL_ARG1(regs)       ((regs)->regs[0])
# define SYSCALL_ARG2(regs)       ((regs)->regs[1])
# define SYSCALL_ARG3(regs)       ((regs)->regs[2])
# define PT_REGS_IP(regs)         ((regs)->pc)
#else
# error "rootkat: unsupported architecture (only x86_64 and arm64)"
#endif
