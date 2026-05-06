#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_link.h>
#include <unistd.h>
#include "common.h"
#include <errno.h>
#include <xdp/libxdp.h>
#include <poll.h>
#include <stdlib.h>
#include <xdp/libxdp.h>
#include <poll.h>
#include <linux/if_link.h>

#include<stdio.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include <stdlib.h>
#include <errno.h>
#include <xdp/libxdp.h>
#include <poll.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#define NUM_FRAMES 10

struct xsk_ring_prod fq, tq;
struct xsk_ring_cons cq, rq;
struct xsk_ring_prod fq6, tq6;
struct xsk_ring_cons cq6, rq6;

void print_mac(unsigned char *data) {
    struct ethhdr *eth = (struct ethhdr *)data;
    printf("Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    printf("Dest MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
           eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
}

void process_packet(void *pkt_data, __u32 len,int idx_tx, __u64 addr, struct Value* val) {
    // 1. Map the Ethernet Header
    char* data = (char*) pkt_data;
    struct ethhdr *eth = (struct ethhdr*)data;
    struct iphdr *iph = (struct iphdr*)(data + sizeof(struct ethhdr));
    struct icmphdr *icmp = (struct icmphdr*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (ntohs(eth->h_proto) == ETH_P_IP && icmp->type == ICMP_ECHO) {
            icmp->type = ICMP_ECHOREPLY;
	   uint8_t tmp_mac[ETH_ALEN];
            memcpy(eth->h_dest, val->dmac, ETH_ALEN);
            memcpy(eth->h_source, val->smac, ETH_ALEN);
            // Swap IP addresses
            iph->saddr = val->srcAddr;
            iph->daddr = val->dstAddr;
            // Change to Echo Reply
            // Update ICMP Checksum (Incremental update 8 -> 0)
	    icmp->type = ICMP_ECHOREPLY;
icmp->checksum = 0;
__u32 icmp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
__u32 sum = 0;
__u16 *p = (__u16 *)icmp;
for (__u32 i = 0; i < icmp_len / 2; i++) sum += ntohs(p[i]);
if (icmp_len & 1) sum += ((__u8 *)icmp)[icmp_len - 1] << 8;
while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
icmp->checksum = htons(~sum & 0xffff);
	    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tq6, idx_tx);
            tx_desc->addr = addr;
	    tx_desc->len = len;
	    tx_desc->options = 0;
	    print_mac(pkt_data);
    }
}

int main(){
	char filename[] = "kernel.bpf.o";
        DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                .open_filename = filename,
        );
        struct xdp_program *prog = xdp_program__create(&xdp_opts);
	struct bpf_map *map  = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog),  "xsks_map");
	int xsk_map_fd = bpf_map__fd(map);
	int ifindex6 = if_nametoindex("ens6");
	int ifindex7 = if_nametoindex("ens7");
	int err = xdp_program__attach(prog, ifindex7, 0 , 0);
        printf("Attach Err %d\n", err);
	if (err) {
		return err;
	}	
	__u32 srcIP;
	inet_pton(AF_INET,"192.103.0.174",&srcIP);
	__u8 smac[6] = {0x0e, 0xe4, 0xc2, 0xf7, 0x2f, 0xf1};
	__u32 dstIP;
	inet_pton(AF_INET,"192.103.0.25",&dstIP);
	__u8 dmac[6] = {0x0e, 0x43, 0x83, 0x8c, 0x5d, 0x15};
	
	struct Value val;
	val.srcAddr = srcIP; 
	val.dstAddr = dstIP;
	memcpy(val.smac, smac ,6);
	memcpy(val.dmac, dmac ,6);
	val.interface_index =  ifindex6;
	map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "controlplane");
	int controlplane_map = bpf_map__fd(map);
	if (controlplane_map < 0) {
    		fprintf(stderr, "map 'controlplane' not found\n");
    		return -1;
	}

	struct ipv4_lpm_key key = { .prefixlen = 24 };
	inet_pton(AF_INET, "192.102.1.0", &key.addr);
	int ret = bpf_map_update_elem(controlplane_map, &key, &val, BPF_ANY);	

	__u32 queue_id = 0 ;
	char* ifname = "ens7";
	void* bufs;
	posix_memalign(&bufs, getpagesize(), NUM_FRAMES * getpagesize());
	printf("\n XSK_UMEM_CREATE \n");	
	struct xsk_umem* umem = NULL;
	ret = xsk_umem__create(&umem, bufs, NUM_FRAMES * getpagesize(), &fq, &cq, NULL);
	if(ret != 0){
		printf("XSK_UMEM_CREATE \n");
	}
	struct xsk_socket_config config = {	
						.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    						.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    						.libbpf_flags = 0,
    						.xdp_flags = XDP_FLAGS_DRV_MODE,
    						.bind_flags = XDP_USE_NEED_WAKEUP,
	};
	struct xsk_socket* xsk;
	printf("Before Ret \n");
	ret = xsk_socket__create(&xsk, ifname, queue_id, umem, &rq, &tq, &config);

	char* ifname6 = "ens6";
	struct xsk_socket* xsk6;
	ret = xsk_socket__create_shared(&xsk6, ifname6, queue_id, umem,
                                &rq6, &tq6, &fq6, &cq6, &config);
	if(ret){
		printf("Ret %d\n", ret);
	}
	//ret = xsk_socket__create(&xsk6, ifname6, queue_id, umem, &rq6, &tq6, &config);
	struct pollfd fds[1] = {
				{ .fd = xsk_socket__fd(xsk), .events = POLLIN }
	};
	while(1){
		int idx = 0;
		int nb = 1;
		xsk_ring_prod__reserve(&fq, nb, &idx);
		for(int i = 0;i<nb;i++){
			printf("\n OFFSET DONE \n");
			*xsk_ring_prod__fill_addr(&fq, idx+i) =  getpagesize();
		}
		xsk_ring_prod__submit(&fq, nb);
		poll(fds, 1, -1);
		int recv = xsk_ring_cons__peek(&rq, nb, &idx);
		for(int i = 0; i<recv; i++){
			const struct xdp_desc* d = xsk_ring_cons__rx_desc(&rq, idx+i);
			__u64 addr = d->addr;
			__u32 len = d->len;
			
			printf("XDP Dsc addr %llu Len %d \n", addr, len);

			void *pkt = xsk_umem__get_data(bufs, d->addr);
			struct ethhdr *eth = pkt;
			struct iphdr *ip = (struct iphdr*)(eth+1);
			char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
			inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
			printf("SRC %s DST %s\n", src, dst);
			struct ipv4_lpm_key key = { .prefixlen = 32 };
			inet_pton(AF_INET, src, &key.addr);
			struct Value val;
			int lret = bpf_map_lookup_elem(controlplane_map, &key, &val);
			printf("lookup ret=%d for src=%s\n", lret, src);
   			if (lret != 0) continue;
			int nb = 1;
			int tx_idx = 0;
			printf("\n Before prod ring reserver TQ6 \n");
			unsigned int n = xsk_ring_prod__reserve(&tq6, 1, &tx_idx);
			if (n != 1) {
				printf("\n Nahi ho rha reserve \n");
			    // drain CQ and retry, or drop this packet
			    continue;
			}
			printf("\n Process PAcket \n");
			process_packet(pkt, len, tx_idx, addr, &val );	
			printf("\n Process PAcket Submit \n");
			xsk_ring_prod__submit(&tq6, nb);
			if (xsk_ring_prod__needs_wakeup(&tq6)){
				printf("\n Sendto \n");
            			sendto(xsk_socket__fd(xsk6), NULL, 0, MSG_DONTWAIT, NULL, 0);
			}
			printf("\n Done needs wakeup \n");
        		// Drain completion queue
        		__u32 cq_idx;
        		int completed = xsk_ring_cons__peek(&cq6, 1, &cq_idx);
			printf("Completed === %d\n", completed);
        		if (completed > 0)
            			xsk_ring_cons__release(&cq6, completed);
		}
            	xsk_ring_cons__release(&rq, recv);
		sleep(1);

	}
	return 0;
}

