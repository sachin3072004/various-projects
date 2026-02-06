#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char license1[] SEC("license") = "GPL"; 
struct Key{
	__u16 proto;
	__u8 src[6];
};

struct Value{
	__u64 count;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct Key);
	__type(value, struct Value);
} hmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_XSKMAP);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 64);
} src1  SEC(".maps");

SEC("xdp")
int capture_pkt(struct xdp_md* ctx){
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

    	struct ethhdr *eth = data;
	if((void*)(eth + 1) > data_end)
		return XDP_ABORTED;

	int proto = bpf_ntohs(eth->h_proto);
	struct Key k;
	__builtin_memcpy(k.src, eth->h_source, 6);
	k.proto = proto;
	struct Value *v = bpf_map_lookup_elem(&hmap, &k);
	if(!v){
		struct Value init = {.count = 1};
		bpf_map_update_elem(&hmap,&k,&init, BPF_ANY);
	}else{
		__sync_fetch_and_add(&v->count, 1);
	}
	if(proto == 2048){
		int index = ctx->rx_queue_index;
		bpf_printk("Index == %d\n",index);
		 if (bpf_map_lookup_elem(&src1, &index)){
			 bpf_printk(" Socket hai\n");
                	return bpf_redirect_map(&src1, index, 0);
		 }else{
			 bpf_printk("Sorry No Socket\n");
		 }

	}
	return XDP_PASS;
}
