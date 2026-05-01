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
#include <errno.h>

void put_host(int map_fd, __u32 key,__u32 srcIP,__u8* smac, __u32 dstIP, __u8* dmac){
	struct IPInfo ipInfo = {};
	ipInfo.daddr = dstIP;
	ipInfo.saddr = srcIP;
	memcpy(ipInfo.dmac, dmac, 6);	
	memcpy(ipInfo.smac, smac, 6);	
	int err = bpf_map_update_elem(map_fd, &key, &ipInfo, BPF_ANY);
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
	__u32 key = 0;
	inet_pton(AF_INET,"192.103.0.25",&key);
	__u32 srcIP;
	inet_pton(AF_INET,"192.102.1.231",&srcIP);
	__u8 smac[6] = {0x0e,0x1a,0xfa,0x99,0xd5,0xf1};
	__u32 dstIP;
	inet_pton(AF_INET,"192.102.1.32",&dstIP);
	__u8 dmac[6] = {0x0e,0x06,0xfc,0x9e,0x45,0xd9};
	put_host(map_fd,key,srcIP, smac, dstIP, dmac);	

	int ifindex6 = if_nametoindex("ens6");
	int ifindex7 = if_nametoindex("ens7");
	key = 0;
	/*int map_fd1 = bpf_obj_get("/sys/fs/bpf/tx_port");
	if (map_fd1 < 0) {
    		fprintf(stderr, "bpf_obj_get tx_port failed: %s\n", strerror(errno));
		return 1;
	}
	printf("MAP_FD1 %d\n", map_fd1);
	bpf_map_update_elem(map_fd1, &key, &ifindex7, BPF_ANY);*/
	int tx_port_fd = bpf_object__find_map_fd_by_name(obj, "tx_port");
	if (tx_port_fd < 0) {
    		fprintf(stderr, "tx_port map not found\n");
    		return 1;
	}
	key = 0;
	int err = bpf_map_update_elem(tx_port_fd, &key, &ifindex7, BPF_ANY);
	if (err) {
    		fprintf(stderr, "tx_port update failed: %s\n", strerror(errno));
    		return 1;
	}
	struct bpf_link *link6 = bpf_program__attach_xdp(prog, ifindex6);
	struct bpf_link *link7 = bpf_program__attach_xdp(prog, ifindex7);
	while(1){
		sleep(5);
	}
	bpf_link__destroy(link6);
	bpf_link__destroy(link7);
	bpf_object__close(obj);
}
