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


void put_host(int map_fd, __u32 ip, __u8* mac){
	struct IPInfo ipInfo = {};
	ipInfo.ip = ip;
	memcpy(ipInfo.mac, mac, 6);	
	int err = bpf_map_update_elem(map_fd, &ip, &ipInfo, BPF_ANY);
	if(err){
		fprintf(stderr,"Map Update Failed \n");
		return;
	}

}

int main(){
	struct bpf_object *obj = bpf_object__open_file("kernel.bpf.o",0);
	bpf_object__load(obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "pass_between");
	
	int map_fd = bpf_object__find_map_fd_by_name(obj, "ipinformation");
	if(map_fd < 0){
		fprintf(stderr, "Map Not Found\n");
		return 1;
	}
	__u32 ip1;
	inet_pton(AF_INET,"10.0.0.1",&ip1);
	__u8 mac1[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
	put_host(map_fd, ip1, mac1);	

	__u32 ip2;
	inet_pton(AF_INET,"10.0.0.2",&ip2);
	__u8 mac2[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
	put_host(map_fd, ip2, mac2);	

	int ifindex = if_nametoindex("ens7");
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	while(1){
		sleep(5);
	}
	bpf_link__destroy(link);
	bpf_object__close(obj);
}
