// SPDX-License-Identifier: MIT
/*
 * Helper: bind a TCP port and listen. argv[2..] flags:
 *   "hide"  send the rootkat hide-port magic signal after binding
 *   "v6"    bind on AF_INET6 (default is AF_INET)
 * Either order; both flags can be combined. Without args, just listens.
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
		fprintf(stderr, "usage: %s <port> [hide] [v6]\n", argv[0]);
		return 1;
	}
	int port = atoi(argv[1]);
	int hide = 0, v6 = 0;
	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "hide")) hide = 1;
		else if (!strcmp(argv[i], "v6")) v6 = 1;
	}

	int s = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
	if (s < 0) { perror("socket"); return 1; }
	int one = 1;
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	int rc;
	if (v6) {
		struct sockaddr_in6 a6 = {
			.sin6_family = AF_INET6,
			.sin6_port   = htons(port),
			.sin6_addr   = IN6ADDR_ANY_INIT,
		};
		/* Listen on v6 only — don't dual-bind, so the v4 hook can't
		 * accidentally hide a v6-only listener via its v4-mapped row. */
		setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
		rc = bind(s, (struct sockaddr *)&a6, sizeof(a6));
	} else {
		struct sockaddr_in a4 = {
			.sin_family = AF_INET,
			.sin_port   = htons(port),
			.sin_addr   = { .s_addr = INADDR_ANY },
		};
		rc = bind(s, (struct sockaddr *)&a4, sizeof(a4));
	}
	if (rc < 0) {
		fprintf(stderr, "bind(%d, %s): %s\n",
		        port, v6 ? "v6" : "v4", strerror(errno));
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
