#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "common.h"

char l1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct IPInfo);
	__uint(max_entries, 1024);

} ipinformation SEC(".maps");

static long find_by_ip(struct bpf_map *map, const void* key, struct IPInfo* val){
	bpf_printk("Key %u \n", *((__u32*)(key)));
	bpf_printk("Val %u %d %d %d %d %d %d \n", val->ip, val->mac[0], val->mac[1], val->mac[2], val->mac[3], val->mac[4], val->mac[5]);
	return 0;
}

SEC("xdp")
int pass_between(struct xdp_md *ctx){
	bpf_for_each_map_elem(&ipinformation, find_by_ip, NULL, 0);
	return XDP_PASS;
}
