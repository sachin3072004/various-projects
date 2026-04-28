// loader.c — minimal
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct bpf_object *obj = bpf_object__open_file("xdp_syncookie.bpf.o", NULL);
    bpf_object__load(obj);
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "syncookie_xdp");
    int ifindex = if_nametoindex("ens7");
    bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_DRV_MODE, NULL);
    pause();
}
