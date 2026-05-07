// SPDX-License-Identifier: MIT
/*
 * Helper: bind a SOCK_STREAM AF_UNIX socket at the given filesystem path
 * and listen, then print "ready" and pause. Used by test_unix_hide.sh
 * to exercise rootkat's /proc/net/unix hiding.
 *
 * usage: unix_helper <path>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <path>\n", argv[0]);
		return 1;
	}
	const char *path = argv[1];

	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	if (strlen(path) >= sizeof(addr.sun_path)) {
		fprintf(stderr, "path too long\n");
		return 1;
	}
	strcpy(addr.sun_path, path);

	/* Be friendly to repeated runs: clear any leftover socket file. */
	unlink(path);

	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) { perror("socket"); return 1; }

	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind(%s): %s\n", path, strerror(errno));
		return 1;
	}
	if (listen(s, 1) < 0) {
		perror("listen");
		return 1;
	}

	puts("ready");
	fflush(stdout);

	pause();
	return 0;
}
