// SPDX-License-Identifier: MIT
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <filename-to-hide>\n", argv[0]);
		return 1;
	}

	struct bpf_object *obj = bpf_object__open_file("hide_file.bpf.o", NULL);
	if (libbpf_get_error(obj)) { perror("open"); return 1; }
	if (bpf_object__load(obj))  { perror("load"); return 1; }

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "hidden_name");
	if (!map) { fprintf(stderr, "map not found\n"); return 1; }

	char buf[64] = {0};
	strncpy(buf, argv[1], sizeof(buf) - 1);
	__u32 key = 0;
	if (bpf_map__update_elem(map, &key, sizeof(key), buf, sizeof(buf), 0)) {
		perror("map update");
		return 1;
	}

	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "hide_file_open");
	if (!prog) { fprintf(stderr, "prog not found\n"); return 1; }

	struct bpf_link *link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) { perror("attach"); return 1; }

	signal(SIGINT,  on_sig);
	signal(SIGTERM, on_sig);
	printf("hiding '%s' (Ctrl-C to stop)\n", buf);
	while (!stop) pause();

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
