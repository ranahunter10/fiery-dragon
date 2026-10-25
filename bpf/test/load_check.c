// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
/*
 * load_check: open a BPF object with libbpf and load every program in it,
 * so the kernel's verifier judges them. Nothing is attached. Prints one line
 * per program and exits non-zero if the object fails to open or load.
 *
 * CI uses it instead of `bpftool prog loadall`, because the runner's bpftool
 * comes from a kernel-specific package that may not exist for its kernel.
 *
 * Usage: load_check OBJECT.bpf.o
 */
#include <stdio.h>
#include <bpf/libbpf.h>

static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list ap)
{
	return level == LIBBPF_DEBUG ? 0 : vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err, n = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: %s OBJECT.bpf.o\n", argv[0]);
		return 2;
	}
	libbpf_set_print(print_libbpf);
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed\n", argv[1]);
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load %s failed: %d\n", argv[1], err);
		bpf_object__close(obj);
		return 1;
	}
	bpf_object__for_each_program(prog, obj) {
		printf("loaded %-24s section %-32s fd %d\n", bpf_program__name(prog),
		       bpf_program__section_name(prog), bpf_program__fd(prog));
		n++;
	}
	bpf_object__close(obj);
	printf("%d programs accepted by the verifier\n", n);
	return n > 0 ? 0 : 1;
}
