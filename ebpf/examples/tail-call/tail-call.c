// xdp_tail_user.c
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t exiting = 0;

static void sigint_handler(int signo)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    const char *iface = "ens7";   // change to your interface
    const char *obj_file = "tail-call.bpf.o";
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_entry = NULL;
    struct bpf_program *prog_tail = NULL;
    struct bpf_map *jmp_map = NULL;
    int prog_entry_fd = -1;
    int prog_tail_fd = -1;
    int jmp_map_fd = -1;
    int ifindex;
    int err;
    __u32 index = 0;

    if (argc > 1)
        iface = argv[1];

    ifindex = if_nametoindex(iface);
    if (!ifindex) {
        fprintf(stderr, "ERROR: unknown iface %s\n", iface);
        return 1;
    }

    // Open BPF object
    obj = bpf_object__open_file(obj_file, NULL);
    if (libbpf_get_error(obj)) {
        err = -libbpf_get_error(obj);
        fprintf(stderr, "ERROR: opening BPF object file failed: %d\n", err);
        return 1;
    }

    // Load BPF object (verify & load all programs/maps)
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed: %d\n", err);
        goto cleanup;
    }

    // Find programs by section or by name
    prog_entry = bpf_object__find_program_by_name(obj, "capture_pkt1");
    prog_tail  = bpf_object__find_program_by_name(obj, "capture_pkt2");
    if (!prog_entry || !prog_tail) {
        fprintf(stderr, "ERROR: finding BPF programs failed\n");
        goto cleanup;
    }

    prog_entry_fd = bpf_program__fd(prog_entry);
    prog_tail_fd  = bpf_program__fd(prog_tail);
    if (prog_entry_fd < 0 || prog_tail_fd < 0) {
        fprintf(stderr, "ERROR: getting program FDs failed\n");
        goto cleanup;
    }

    // Find the PROG_ARRAY map that will hold the tail call targets
    jmp_map = bpf_object__find_map_by_name(obj, "hmap");
    if (!jmp_map) {
        fprintf(stderr, "ERROR: finding jmp_table map failed\n");
        goto cleanup;
    }

    jmp_map_fd = bpf_map__fd(jmp_map);
    if (jmp_map_fd < 0) {
        fprintf(stderr, "ERROR: getting jmp_table map FD failed\n");
        goto cleanup;
    }

    // Put xdp_tail_prog FD into index 0 of jmp_table
    index = 0;
    err = bpf_map_update_elem(jmp_map_fd, &index, &prog_tail_fd, 0);
    if (err) {
        fprintf(stderr, "ERROR: updating jmp_table map failed: %s\n", strerror(errno));
        goto cleanup;
    }

    // Attach entry program as XDP to interface
    err = bpf_xdp_attach(ifindex, prog_entry_fd, XDP_FLAGS_DRV_MODE, NULL);
    if (err) {
        fprintf(stderr, "ERROR: attaching XDP program to %s failed: %d\n", iface, err);
        goto cleanup;
    }

    printf("XDP tail-call setup loaded on %s (ifindex %d)\n", iface, ifindex);
    printf("Press Ctrl+C to exit\n");

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    while (!exiting) {
        sleep(1);
    }

    printf("Detaching XDP program...\n");
    bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);

cleanup:
    if (obj)
        bpf_object__close(obj);
    return err != 0;
}

