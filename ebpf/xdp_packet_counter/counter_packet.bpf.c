#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char l1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
}pkt_count_per_cpu SEC(".maps");

struct Event {
	__u32 ip_addr;
	__u64 count;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");


SEC("xdp")
int capture_pkt(struct xdp_md* ctx){
	void* data = (void *)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = data;
	if((void*)(eth + 1) > data_end){
		return XDP_PASS;
	}
	bpf_printk("Src MAC %x:%x:%x:%x:%x:%x", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
	bpf_printk("Dest MAC %x:%x:%x:%x:%x:%x", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
	__u16 proto =   bpf_ntohs(eth->h_proto);
	bpf_printk("Capture_pkt %d \n", proto);
	struct iphdr *iph = data + sizeof(struct ethhdr);
	if((void*)(iph + 1) >= data_end){
		return XDP_PASS;
	}
	__u32 saddr = iph->saddr;
	__u32 daddr = iph->daddr;
	__u64 *value = bpf_map_lookup_elem(&pkt_count_per_cpu, &saddr);
	if(value) {
		__u64 increase = 1;
		 __sync_fetch_and_add(value, increase);
		if(*value % 5 == 0){
			struct Event e = {.ip_addr = saddr, .count = *value};
			bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,&e, sizeof(e));
		}
	}else{
		__u64 newval = 1;
		bpf_map_update_elem(&pkt_count_per_cpu, &saddr, &newval, BPF_NOEXIST);
	}
	bpf_printk("The source IP is: %pI4 Dst %pI4 \n", &saddr, &daddr);
	return XDP_PASS;
}

