#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <unistd.h>
#include "common.h"


void put_host(int map_fd, __u32 srcIP,__u32 dstIP, __u8* mac){
	struct IPInfo ipInfo = {};
	ipInfo.daddr = dstIP;
	memcpy(ipInfo.mac, mac, 6);	
	int err = bpf_map_update_elem(map_fd, &srcIP, &ipInfo, BPF_ANY);
	if(err){
		fprintf(stderr,"Map Update Failed \n");
		return;
	}

}

int main(){
	struct bpf_object *obj = bpf_object__open_file("kernel.bpf.o",0);
	bpf_object__load(obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "pass_between");
	
	int map_fd = bpf_object__find_map_fd_by_name(obj, "controlplane");
	if(map_fd < 0){
		fprintf(stderr, "Map Not Found\n");
		return 1;
	}
	__u32 srcIP;
	inet_pton(AF_INET,"192.102.1.32",&srcIP);
	__u32 dstIP;
	inet_pton(AF_INET,"192.102.1.65",&dstIP);
	__u8 mac1[6] = {0x0e,0x08,0xd2,0x6e,0xaf,0x05};
	put_host(map_fd, srcIP, dstIP, mac1);	

	inet_pton(AF_INET,"192.103.0.25",&srcIP);
	put_host(map_fd,srcIP, dstIP, mac1);	

	int ifindex6 = if_nametoindex("ens6");
	struct bpf_link *link6 = bpf_program__attach_xdp(prog, ifindex6);

	int ifindex7 = if_nametoindex("ens7");
	struct bpf_link *link7 = bpf_program__attach_xdp(prog, ifindex7);
	while(1){
		sleep(5);
	}
	bpf_link__destroy(link6);
	bpf_link__destroy(link7);
	bpf_object__close(obj);
}
