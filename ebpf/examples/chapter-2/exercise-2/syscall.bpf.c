#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char license1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, char[64]);
} hmap SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u32);
        __uint(max_entries, 2);
} meta_map SEC(".maps");

void* getIndex(){
        __u32 index = 0;
        __u64 val = 0;
        void* elem = bpf_map_lookup_elem(&meta_map,&index);
        if(!elem){
                __u32 key = index;
                __u32 val = 0;
                long success = bpf_map_update_elem(&meta_map,&key, &val, BPF_NOEXIST);
                if(success == 0){
                        bpf_printk("\n Success \n");
                }else{
                        bpf_printk("\n Failure \n");
                }
                elem = bpf_map_lookup_elem(&meta_map,&index);
        }
        return elem;

}

SEC("tp/syscalls/sys_enter_openat")
int enter_openat2(struct trace_event_raw_sys_enter *ctx){
	bpf_printk("ID %d \n", ctx->id);
	bpf_printk("ArgsX %d \n", ctx->args[0]);
	char str[64] = {'\0'};
	bpf_probe_read_user_str(str, 64, (void*)ctx->args[1]);
	bpf_printk("Result %s\n",str);
	void* index = getIndex();
        if(index){
                long success = bpf_map_update_elem( &hmap, index, str, BPF_ANY);
                __sync_fetch_and_add((__u32*)index, 1);
        }
	return 0;
}

