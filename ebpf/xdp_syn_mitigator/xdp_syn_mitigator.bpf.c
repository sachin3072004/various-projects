#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char l1[] SEC("license") = "GPL";
#define TCP_PROTOCOL 6
#define interval 20000000000
#define THRESHOLD 100
#define penality_timer 5000000000

struct Entry {
	__u64 start;
	__u64 count;
	__u64 blocked_for;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u32);
	__type(value, struct Entry);
	__uint(max_entries, 1024);
} record SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 1024);
    __type(key, uint32_t);
    __type(value, uint64_t);
} pkt_stats SEC(".maps");

static __always_inline
void update_stats(int state){
	__u64 *val = bpf_map_lookup_elem(&pkt_stats, &state);
	if(val){
		*val += 1;
		if(state){
			bpf_printk(" DROP %lu \n", *val);
		}else{
			bpf_printk(" PASS %lu \n", *val);
		}
	}else{
		__u64 v = 1;
		bpf_map_update_elem(&pkt_stats, &state, &v, BPF_ANY);
	}
}

enum State {
	Pass = 0,
	Drop = 1,
};

SEC("xdp")
int filter_syn_packets(struct xdp_md* ctx){
	void* data = (void*)(long)ctx->data;
	void* data_end = (void*)(long)ctx->data_end;
	struct ethhdr *eth = (struct ethhdr*)data;
	if((void*)(eth + 1) > data_end){
		return XDP_PASS;
	}
	struct iphdr* iphdr = (struct iphdr*)((char*)data + sizeof(struct ethhdr));
	if((void*)(iphdr + 1) > data_end){
		return XDP_PASS;
	}
	__u32 saddr = iphdr->saddr;
	__u8 *ipStart = (__u8*)&saddr;
	__u8 protocol = iphdr->protocol;
	if(protocol != TCP_PROTOCOL){
		return XDP_PASS;
	}
	struct tcphdr* tcp =  (struct tcphdr*)((char*)data + sizeof(struct ethhdr) + sizeof(struct iphdr));
	if((void*)(tcp + 1) > data_end){
		return XDP_PASS;
	}
	struct Entry *val;
	val = bpf_map_lookup_elem(&record, &saddr);
	__u64 now = bpf_ktime_get_ns();
	if(!val){
		struct Entry e = {.start = now, .count = 1, .blocked_for = 0 };
		bpf_map_update_elem(&record, &saddr, &e, BPF_ANY);
		update_stats(Pass);
		return XDP_PASS;
	}else if(val->blocked_for > now){
		update_stats(Drop);
		return XDP_DROP;
	}else if(val->start + interval < now ){
		struct Entry e = {.start = now, .count = 1, .blocked_for = 0 };
		bpf_map_update_elem(&record, &saddr, &e, BPF_ANY);
		update_stats(Pass);
		return XDP_PASS;
	}else if(val->start + interval > now) {
		if(val->count <= THRESHOLD){
			__sync_fetch_and_add(&(val->count), 1);
			update_stats(Pass);
			return XDP_PASS;
		}else{
			val->blocked_for = now + penality_timer;
			update_stats(Drop);
			return XDP_DROP;
		}
	}
	return XDP_PASS;
}
