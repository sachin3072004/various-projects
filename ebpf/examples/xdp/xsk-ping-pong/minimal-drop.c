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

struct xsk_ring_prod fx, tx;
struct xsk_ring_cons rx, cx;
bool exiting = false;
void handle_exit(){
	exiting = true;
}

void print_mac(unsigned char *data) {
    struct ethhdr *eth = (struct ethhdr *)data;
    printf("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->h_source[0], eth->h_source[1], eth->h_source[2],
           eth->h_source[3], eth->h_source[4], eth->h_source[5]);
}

void process_packet(void *pkt_data, __u32 len,int idx_tx, __u64 x) {
    // 1. Map the Ethernet Header
    char* data = (char*) pkt_data;
    struct ethhdr *eth = (struct ethhdr*)data;
    struct iphdr *iph = (struct iphdr*)(data + sizeof(struct ethhdr));
    struct icmphdr *icmp = (struct icmphdr*)(data + sizeof(struct ethhdr) + sizeof(struct iphdr));
    if (ntohs(eth->h_proto) == ETH_P_IP && icmp->type == ICMP_ECHO) {
	   uint8_t tmp_mac[ETH_ALEN];
            memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, tmp_mac, ETH_ALEN);

            // Swap IP addresses
            uint32_t tmp_ip = iph->saddr;
            iph->saddr = iph->daddr;
            iph->daddr = tmp_ip;

            // Change to Echo Reply
            icmp->type = ICMP_ECHOREPLY;
            
            // Update ICMP Checksum (Incremental update 8 -> 0)
            uint32_t csum = icmp->checksum;
            csum += htons(ICMP_ECHO << 8);
            icmp->checksum = (csum & 0xFFFF) + (csum >> 16);
	    struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx, idx_tx);
            tx_desc->addr = x;
	    tx_desc->len = len;
    }
}

int main(){
	/*struct bpf_object *obj = bpf_object__open_file("minimal-drop.bpf.o", NULL);
	if(!obj){
		printf("File not found");
		return 0;
	}
	int err = bpf_object__load(obj);
	if(err){
		printf("Err %s", strerror(err));
		return 0;
	}
	struct bpf_program *prog = bpf_object__find_program_by_name(obj,"capture_pkt");
	struct bpf_link* link = bpf_program__attach_xdp(prog, index);*/
	char ifname[] = "ens7";
	unsigned int ifindex = if_nametoindex(ifname);
	int FRAME_SIZE = getpagesize();
	 //////////////////////
	 char errmsg[1024] = {'\0'};
        char filename[] = "minimal-drop.bpf.o";
         DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                        .open_filename = filename,
                );
                struct bpf_map *map;

                struct xdp_program *prog = xdp_program__create(&xdp_opts);
                int err = libxdp_get_error(prog);
                printf("Err %d\n", err);
                if (err) {
                        libxdp_strerror(err, errmsg, sizeof(errmsg));
                        fprintf(stderr, "ERR: loading program: %s\n", errmsg);
                        return err;
                }
                  err = xdp_program__attach(prog, ifindex, 0 , 0);
                printf("Attach Err %d\n", err);
                if (err) {
                        libxdp_strerror(err, errmsg, sizeof(errmsg));
                        fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
                                ifname, errmsg, err);
                        return err;
                }

                /* We also need to load the xsks_map */
                map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "xsk_map");
                int xsk_map_fd = bpf_map__fd(map);
                printf("XSK_MAP_FD %d\n", xsk_map_fd);
                if (xsk_map_fd < 0) {
                        fprintf(stderr, "ERROR: no xsks map found: %s\n",
                                strerror(xsk_map_fd));
                        exit(EXIT_FAILURE);
                }
        /////////////////////////
	///////////////
	void* buffer;
	size_t page_size = getpagesize();
	size_t buffer_size = 10 * page_size;

	// Allocate a buffer aligned to the system's page size
	if (posix_memalign(&buffer, page_size, buffer_size) != 0) {
    		perror("Failed to allocate page-aligned memory");
    		exit(EXIT_FAILURE);
	}
	struct xsk_umem* umem = NULL;

	xsk_umem__create(&umem, buffer, buffer_size,&fx, &cx, NULL);
	printf("Umem %p\n", umem);
	struct xsk_socket *xsk;
	int queue_id = 0;
	struct xsk_socket_config config = {
    .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
    .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
    .libbpf_flags = 0,
    .xdp_flags = XDP_FLAGS_DRV_MODE, // Example: Hardware mode
    .bind_flags = XDP_USE_NEED_WAKEUP, // Set the flag here
};
	int ret = xsk_socket__create(&xsk, ifname, queue_id, umem, &rx, &tx, &config);
	printf("RET %d\n", ret);
	int nb = 6;
	int idx = 0;
	xsk_ring_prod__reserve(&fx, nb, &idx);
	for(int i = 0;i<nb;i++){
		idx += i; 
		*xsk_ring_prod__fill_addr( &fx, idx ) = i * getpagesize();
	}
	xsk_ring_prod__submit(&fx, nb);
	int rx_nb = 1;
	int rx_idx = -100;
	struct pollfd fds[1];
	fds[0].fd = xsk_socket__fd(xsk);
	fds[0].events = POLLIN;
	int totalRcvd = 0;
	int x = 0;
	int idx_tx = 0;
	while(!exiting){
		ret = poll(fds, 1, -1);
		__u32 rcvd = xsk_ring_cons__peek(&rx, rx_nb, &rx_idx);
		totalRcvd += rcvd;
		printf("RCVD %d rx_idx %d totalRcvd %d \n", rcvd, rx_idx, totalRcvd);
		for(int i = 0; i < rcvd; i++){
			const struct xdp_desc* dsc = xsk_ring_cons__rx_desc(&rx, rx_idx+i);
			__u64 addr = dsc->addr;
			__u32 len = dsc->len;
			
			addr = xsk_umem__add_offset_to_addr(addr);
			printf("XDP Dsc addr %llu Len %d \n", addr, len);
			void *pkt_data = xsk_umem__get_data(buffer, dsc->addr);
			uint32_t tx_batch = xsk_ring_prod__reserve(&tx, rcvd, &idx_tx);
			printf("IDX_TX %d\n",idx_tx);
			process_packet(pkt_data, dsc->len, idx_tx, addr);
			printf("Before Cached prod %d cached_cons %d Size %d PRoducer %d consumer %d\n ",rx.cached_prod, rx.cached_cons,rx.size,*rx.producer, *rx.consumer);
			xsk_ring_cons__release(&rx, rcvd);
			/////////
			// 5. Kick the kernel to send the packets
			//
			printf("After Cached prod %d cached_cons %d Size %d PRoducer %d consumer %d \n",rx.cached_prod, rx.cached_cons,rx.size,*rx.producer, *rx.consumer);

		}
		xsk_ring_prod__submit(&tx, rcvd);
		//if (xsk_ring_prod__needs_wakeup(&tx)) {
			//printf("Woken up to send\n");
			//sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		//}
		if(totalRcvd == 5){
			xsk_ring_prod__reserve(&fx, totalRcvd, &idx);
			printf("REserve IDX === %d\n",idx);
			for(int i = 0;i<totalRcvd;i++){
				*xsk_ring_prod__fill_addr( &fx, idx + i) = i * getpagesize();
			}
			xsk_ring_prod__submit(&fx, totalRcvd);
			totalRcvd = 0;
		}
		x += 1;
		if(x >= 100){
			exiting = true;
		}
	}
	/////////////////
	while(!exiting){
		sleep(5);
	}
	//xdp_link__destroy(link);
}
