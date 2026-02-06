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

//Execute below commands before running this
//sudo ifconfig ens7 mtu 1500 up
//sudo ethtool -L ens7 combined 2
bool exiting = false;
void handle_signal(){
	exiting = true;
}
struct Key{
        __u16 proto;
        __u8 src[6];
};
struct Value{
	__u64 count;
};
static void print_mac(__u16 proto, const unsigned char *m,__u64 count){
        printf("Proto %u Src Mac%02x:%02x:%02x:%02x:%02x:%02x Count %llu \n",proto, m[0],m[1],m[2],m[3],m[4],m[5], count);
}
static struct xdp_program *prog;
struct xsk_socket *xsk;
#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE

	struct xsk_ring_prod fq, tx;
	struct xsk_ring_cons cq, rx;
static uint16_t csum16(const void *buf, size_t len)
{
	uint32_t sum = 0;
	const uint16_t *p = buf;

	while (len > 1) {
	sum += *p++;
	len -= 2;
	}
	if (len == 1) {
		uint16_t last = 0;
		*(uint8_t *)&last = *(const uint8_t *)p;
		sum += last;
	}
	while (sum >> 16)
	sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

/* pkt must contain: Ethernet + IPv4 + ICMP Echo Request (+payload) */
int make_icmp_echo_reply(void *pkt, size_t len)
{
	if (len < sizeof(struct ethhdr) + sizeof(struct iphdr) +
	sizeof(struct icmphdr))
	return -1;

	struct ethhdr *eth = (struct ethhdr *)pkt;
	if (ntohs(eth->h_proto) != ETH_P_IP)
	return -1;

	struct iphdr *ip = (struct iphdr *)(eth + 1);
	if (len < sizeof(struct ethhdr) + ip->ihl * 4 + sizeof(struct icmphdr))
	return -1;

	if (ip->protocol != IPPROTO_ICMP)
	return -1;

	size_t ip_hdr_len = ip->ihl * 4;
	struct icmphdr *icmp = (struct icmphdr *)((uint8_t *)ip + ip_hdr_len);
	size_t icmp_len = ntohs(ip->tot_len) - ip_hdr_len;
	if (sizeof(struct ethhdr) + ip_hdr_len + icmp_len > len)
	return -1;

	if (icmp->type != ICMP_ECHO)
	return -1;

	/* Turn request into reply */
	icmp->type = ICMP_ECHOREPLY;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->checksum = csum16(icmp, icmp_len);

	/* Swap IP addresses */
	uint32_t tmp_ip = ip->saddr;
	ip->saddr = ip->daddr;
	ip->daddr = tmp_ip;

	ip->check = 0;
	ip->check = csum16(ip, ip_hdr_len);

	/* Swap MAC addresses */
	uint8_t tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);

	return 0; /* packet is now an ICMP Echo Reply */
}

bool af_xdp_send_frame(uint64_t addr, uint32_t len)
{
	uint32_t idx;
	int ret;

	ret = xsk_ring_prod__reserve(&tx, 1, &idx);
	if (ret != 1)
		return false;

	struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&tx, idx);
	tx_desc->addr = addr;
	tx_desc->len = len;

	xsk_ring_prod__submit(&tx, 1);

	if (xsk_ring_prod__needs_wakeup(&tx)) {
	ret = sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret < 0)
		return false;
	}

	return true;
}

static void handle_receive_packets(struct xsk_ring_cons *rx,void* packet_buffer)
{
		unsigned int rcvd, stock_frames, i;
		uint32_t idx_rx = 0, idx_fq = 0;
		int ret;

        rcvd = xsk_ring_cons__peek(rx, 100, &idx_rx);
	for (int i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc = xsk_ring_cons__rx_desc(rx, idx_rx + i);
		__u64 addr = desc->addr;
		__u32 len = desc->len;

		addr = xsk_umem__add_offset_to_addr(addr); // handle headroom
		void *data = xsk_umem__get_data(packet_buffer, addr);
		/*if(make_icmp_echo_reply(data, desc->len) == 0){
			if (!af_xdp_send_frame(addr, len)) {}
			else {}
			
		}*/

		/*struct ethhdr *eth = data;
		printf("Proto %d \n", ntohs(eth->h_proto));
		if (ntohs(eth->h_proto) != ETH_P_IP)
		continue;

		struct iphdr *iph = (struct iphdr *)((unsigned char *)data + sizeof(*eth));
		struct in_addr s, d;
		s.s_addr = iph->saddr;
		d.s_addr = iph->daddr;

		char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &s, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET, &d, dst_ip, sizeof(dst_ip));

		printf("src=%s dst=%s len=%u\n", src_ip, dst_ip, len);*/

	}
	printf("Rcvd %d\n", rcvd);
	sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

int main(){
	const char ifname[] = "ens7";
	struct xsk_umem *umem;
	uint64_t packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
	void* packet_buffer;
        if (posix_memalign(&packet_buffer,
                           getpagesize(),
                           packet_buffer_size)) {
                fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                        strerror(errno));
                exit(EXIT_FAILURE);
        }
	xsk_umem__create(&umem, packet_buffer, packet_buffer_size, &fq, &cq, NULL);
	int queue_num = 1;
	
	 char errmsg[1024];
	signal(SIGINT, handle_signal);
	char obj_path[] = "/home/ubuntu/various-projects/ebpf/examples/xdp/xdp-switch/hello.bpf.o";
	signal(SIGINT, handle_signal);
	/*struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "capture_pkt");
	bpf_object__load(obj);

	unsigned int ifindex = if_nametoindex(ifname);
	printf("IfIndex == %d %p \n",ifindex, prog);
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	struct bpf_map *hmap = bpf_object__find_map_by_name(obj,"hmap");
	int map_fd = bpf_map__fd(hmap);
	struct Key next_key, key;*/
	unsigned int ifindex = if_nametoindex(ifname);
	//////////////////////
	char filename[] = "hello.bpf.o";
	 DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                        .open_filename = filename,
                );
                struct bpf_map *map;

                prog = xdp_program__create(&xdp_opts);
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
                map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), "src1");
                int xsk_map_fd = bpf_map__fd(map);
		printf("XSK_MAP_FD %d\n", xsk_map_fd);
                if (xsk_map_fd < 0) {
                        fprintf(stderr, "ERROR: no xsks map found: %s\n",
                                strerror(xsk_map_fd));
                        exit(EXIT_FAILURE);
                }
	/////////////////////////
	int ret = xsk_socket__create(&xsk, ifname,
                                 queue_num, umem, &rx,
                                 &tx, NULL);
	printf("XSK_SOCJET_CREATE %d\n", ret);
	struct pollfd fds[2];
        int nfds = 1;
        memset(fds, 0, sizeof(fds));
        fds[0].fd = xsk_socket__fd(xsk);
        fds[0].events = POLLIN;
	printf("xsk_map_fd === %d\n", xsk_map_fd);
	ret = xsk_socket__update_xskmap(xsk, xsk_map_fd);
	printf("RET %d\n",ret);

	//////////////
        /* Stuff the receive path with buffers, we assume we have enough */
	__u32 idx = 0;
	__u32 nb = 100;
        ret = xsk_ring_prod__reserve(&fq,
                                     nb,
                                     &idx);
	printf("RET %d IDX == %d \n",ret, idx);
        if (ret < nb){
		printf("Not working");
		return 1;	
	}
        for (int i = 0; i < 1024; i ++){
		__u64 addr = i*FRAME_SIZE; 
                *xsk_ring_prod__fill_addr(&fq, i) = addr;
	}
        xsk_ring_prod__submit(&fq,nb);
	///////////////
        while(!exiting) {
		printf("Exiting %d\n",exiting);
                //if (cfg->xsk_poll_mode) {
                        ret = poll(fds, nfds, -1);
			printf("Ret %d\n",ret);
                        if (ret <= 0 || ret > 1)
                                continue;
                //}
                handle_receive_packets(&rx, packet_buffer);
		sleep(3);
        }
	/*ret = xsk_socket__update_xskmap(xsk, xsk_map_fd);
	printf("RET %d\n",ret);*/
	
	//bpf_link__destroy(link);
	//bpf_object__close(obj);


	printf("Cleaning socket");
	xsk_socket__delete(xsk);
        xsk_umem__delete(umem);
        free(packet_buffer);
	return 0;
}
