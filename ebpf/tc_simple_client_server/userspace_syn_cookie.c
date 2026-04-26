#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <net/if.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *ifname = argc > 1 ? argv[1] : "ens7";
    int ifindex = if_nametoindex(ifname);

    struct bpf_object *obj = bpf_object__open_file("bpf_sk_lookup_tcp.bpf.o", NULL);
    bpf_object__load(obj);

    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, "drop_if_no_listener");
    int prog_fd = bpf_program__fd(prog);

    /* Create the clsact qdisc on ifindex (idempotent if it exists). */
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = BPF_TC_INGRESS);
    bpf_tc_hook_create(&hook);   /* ignore -EEXIST */

    /* Attach the program at TC ingress. */
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = prog_fd);
    if (bpf_tc_attach(&hook, &opts)) {
        perror("bpf_tc_attach");
        return 1;
    }

    printf("attached on %s, Ctrl-C to detach\n", ifname);
    pause();
}
