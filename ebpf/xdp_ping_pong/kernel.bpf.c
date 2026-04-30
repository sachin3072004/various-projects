#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"
#include <bpf/bpf_endian.h>

char l1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct IPInfo);
	__uint(max_entries, 1024);

} controlplane SEC(".maps");

static long find_by_ip(struct bpf_map *map, const void* key, struct IPInfo* val){
	bpf_printk("Key %u \n", *((__u32*)(key)));
	bpf_printk("Val %u %d %d %d %d %d %d \n", val->daddr, val->mac[0], val->mac[1], val->mac[2], val->mac[3], val->mac[4], val->mac[5]);
	return 0;
}

static __always_inline __u16 ipv4_csum(struct iphdr *iph) {
	iph->check = 0;
	__u32 csum = 0;
	__u16 *p = (__u16 *)iph;
	#pragma unroll
	for (int i = 0; i < 10; i++) // 20 bytes / 2
		csum += p[i];
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return ~csum;
}

SEC("xdp")
int pass_between(struct xdp_md *ctx){
	void* data = (void *)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if((void*)(eth + 1) > data_end){
		return XDP_PASS;
	}
	__u16 proto =   bpf_ntohs(eth->h_proto);
	if(proto != 2048){
		return XDP_PASS;
	}
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if((void*)(iph + 1) >= data_end){
		return XDP_PASS;
	}
	if(iph->protocol != 1){
		return XDP_PASS;
	}
	__u32 saddr = iph->saddr;
	__u32 daddr = iph->daddr;
	struct IPInfo *value = bpf_map_lookup_elem(&controlplane, &saddr);
	if(value) {
		/*iph->saddr = iph->daddr;
		iph->daddr = value->daddr;
		__builtin_memcpy(&eth->h_source, &eth->h_dest, 6);
		__builtin_memcpy(&eth->h_dest, &value->mac, 6);
		bpf_printk("The source IP is: %pI4 Dst %pI4 MAC %d:%d:%d:%d:%d:%d \n", &saddr, &(value->daddr), (value->mac[0]), 
												(value->mac[1]), (value->mac[2]), 
												(value->mac[3]), (value->mac[4]), 
												(value->mac[5]));*/
		__u32 temp = iph->saddr;
		iph->saddr = iph->daddr;
		iph->daddr = temp;

		iph->ttl -= 10 ;
		iph->check = ipv4_csum(iph);
		__u8 mac[6];
		__builtin_memcpy(mac, eth->h_dest, 6);
		__builtin_memcpy(eth->h_dest, eth->h_source, 6);
		__builtin_memcpy(eth->h_source, mac, 6);
		bpf_printk("Sending back packet TTL %d \n",iph->ttl);
		return XDP_TX;

	}
	return XDP_PASS;
}
