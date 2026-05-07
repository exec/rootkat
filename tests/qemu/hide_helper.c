// SPDX-License-Identifier: MIT
/*
 * Helper: print own PID, send the rootkat hide signal to self, then
 * pause until killed. Used by test_process_hide.sh to verify that a
 * process can disappear from /proc enumeration after the magic signal.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define ROOTKAT_HIDE_SIG 63

int main(void)
{
	pid_t pid = getpid();
	printf("%d\n", pid);
	fflush(stdout);

	if (kill(pid, ROOTKAT_HIDE_SIG) < 0) {
		fprintf(stderr, "kill: %s\n", strerror(errno));
		return 1;
	}

	pause();
	return 0;
}
