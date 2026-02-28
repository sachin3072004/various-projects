#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>

bool exiting = false;
void capture_signal(){
	exiting = true;
}
int main(){
	struct bpf_object *obj = bpf_object__open_file("xdp-hello-world.bpf.o", 0);
	bpf_object__load(obj);
	struct bpf_program* prog = bpf_object__find_program_by_name(obj, "count_pkt");
	int ifindex = if_nametoindex("ens7");
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	struct bpf_map *hmap = bpf_object__find_map_by_name(obj, "hmap");
	signal(SIGINT, capture_signal);
	while(!exiting){
		sleep(1);
	}
	bpf_link__destroy(link);
	bpf_object__close(obj);
}
