#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
char license1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} hmap SEC(".maps");

struct bpf_spin_lock lock;

SEC("xdp")
int count_pkt(void* pkt_ctx){
	bpf_printk("\n Hello World \n");
	__u32 k = 0;
	void *result = bpf_map_lookup_elem(&hmap, &k);
	if(result){
	bpf_spin_lock(&lock);
		__sync_add_and_fetch((int*)result, 1);

	bpf_spin_unlock(&lock);
	}else{
		__u32 v = 0;
		bpf_map_update_elem(&hmap, &k, &v, BPF_ANY);
	}
	return XDP_PASS;
}
