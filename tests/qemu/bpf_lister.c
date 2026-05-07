// SPDX-License-Identifier: MIT
/*
 * Walk all BPF prog IDs the kernel admits to (BPF_PROG_GET_NEXT_ID) and
 * print "<id> <name>" for each. Used by test_bpf_hide.sh to verify that
 * rootkat's sys_bpf hook successfully hides the eBPF program named
 * "hide_file_open" from enumeration.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	__u32 id = 0;
	while (bpf_prog_get_next_id(id, &id) == 0) {
		int fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0)
			continue;
		struct bpf_prog_info info = {0};
		__u32 info_len = sizeof(info);
		if (bpf_prog_get_info_by_fd(fd, &info, &info_len) == 0)
			printf("%u %s\n", id, info.name);
		close(fd);
	}
	return 0;
}
