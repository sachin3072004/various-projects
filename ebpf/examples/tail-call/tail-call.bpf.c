#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u32);
} hmap SEC(".maps"); 

SEC("xdp")
int capture_pkt1(struct xdp_md *ctx){
	bpf_printk("Capture pkt1");
	__u32 index = 0;
	bpf_tail_call(ctx, &hmap, index);
	bpf_printk("Should not reach here");
	return XDP_PASS;
}

SEC("xdp")
int capture_pkt2(struct xdp_md* ctx){
	bpf_printk("Capture pkt2");
	return XDP_PASS;
}
