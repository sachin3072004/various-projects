#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
char license1[] SEC("license") = "GPL";
#define ETH_P_IP 2048

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 1024);
	__type(key,__u32);
	__type(value, __u32);

} xsk_map SEC(".maps");

SEC("xdp")
int capture_pkt(struct xdp_md* ctx){
	char* data = (char*)(long)(ctx->data);
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr* eth = (struct ethhdr*)(data);
	 if((void*)(eth + 1) > data_end)
                return XDP_ABORTED;
	if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
		int index  = ctx->rx_queue_index;
		if(bpf_map_lookup_elem(&xsk_map, &index)){
			return bpf_redirect_map(&xsk_map, index, BPF_ANY);
		}else{
			bpf_printk("Map does not contain %d\n",index);
		}
		/*bpf_printk("Capture_pkt\n");
		struct iphdr* ip = (struct iphdr*)(data + sizeof(struct ethhdr));
	 	if((void*)(ip + 1) > data_end)
                	return XDP_ABORTED;
		bpf_printk("IP %p %p \n", ip, data);
		__u64 src_ip = ip->saddr;
		__u64 dst_ip = ip->daddr;
		bpf_printk("From Char SRC %pI4 DST %pI4 \n", &src_ip, &dst_ip);*/

	}
	return XDP_PASS;
}
