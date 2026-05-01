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

struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u32);

} tx_port SEC(".maps");

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
		bpf_printk("The source IP is: %pI4 Dst %pI4 \n", &(iph->saddr), &(iph->daddr)); 
		iph->saddr = value->saddr;
		iph->daddr = value->daddr;
		__builtin_memcpy(&eth->h_source, &value->smac, 6);
		__builtin_memcpy(&eth->h_dest, &value->dmac, 6);
		bpf_printk("The source IP is: %pI4 Dst %pI4",&(iph->saddr), &(iph->daddr)); 
		bpf_printk("Src MAC %d:%d:%d:%d:%d:%d \n", eth->h_source[0], eth->h_source[1],eth->h_source[2], eth->h_source[3],eth->h_source[4],eth->h_source[5]);
		bpf_printk("Dst Mac %d:%d:%d:%d:%d:%d \n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
		iph->check = ipv4_csum(iph);
		__u32 key = 0;
		void* value1 = bpf_map_lookup_elem(&tx_port, &key);
		if(value1){
			bpf_printk("Value1 %d\n", (*(__u32*)value1));
		}else{
			bpf_printk("Value1 is null \n");
		}
		return bpf_redirect_map(&tx_port, key, 0);
	}
	return XDP_PASS;
}
