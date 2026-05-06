#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char l1[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_XSKMAP);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 64);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, struct Value);
    __uint(max_entries, 1024);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} controlplane SEC(".maps");

SEC("xdp")
int capture_redirect(struct xdp_md *ctx){
	bpf_printk("\n Capture_redirect \n");
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr* ethhdr = data;
	if((void*)(ethhdr+1) > data_end){
		return XDP_PASS;
	}

	__u16 proto = bpf_ntohs(ethhdr->h_proto);
	if(proto != 2048){
		return XDP_PASS;
	}
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if((void*)(iph + 1) > data_end){
		return XDP_PASS;
	}
	if(iph->protocol != 1){
		return XDP_PASS;
	}
	int index = ctx->rx_queue_index;
	bpf_printk("Queue_id %d\n", index);
	if(bpf_map_lookup_elem(&xsks_map, &index)){
		__u64 src_ip = iph->saddr;
		__u64 dst_ip = iph->daddr;
		bpf_printk("Added\n");
		bpf_printk("From Char SRC %pI4 DST %pI4 \n", &src_ip, &dst_ip);
		return bpf_redirect_map(&xsks_map, index, BPF_ANY);
	}else{
		bpf_printk("\n Queue index is not present in XSP_MAP %d \n",index);
	}
	return XDP_PASS;

}
