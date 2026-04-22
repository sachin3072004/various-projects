#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>

int main(){
	struct bpf_object *obj = bpf_object__open_file("xdp_syn_mitigator.bpf.o",0);
	bpf_object__load(obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "filter_syn_packets");
	int ifindex = if_nametoindex("ens7");
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);

	while(1){
		sleep(5);
	}
	bpf_link__destroy(link);
	bpf_object__close(obj);
}
