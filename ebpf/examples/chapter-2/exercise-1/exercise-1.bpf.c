#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char license1[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} odd SEC(".maps"), even SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 2);
} meta_map SEC(".maps");


void* getIndex(bool odd){
	__u32 index = 0;
	__u64 val = 0;
	if(odd){
		index = 0;
	}else{
		index = 1;
	}
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

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_point_execve(void* ctx){
	bpf_printk("Basic \n");
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 pid = pid_tgid >> 32;
	void* index = NULL;
	if(pid % 2 == 0){
		index = getIndex(false);
		if(index){
			bpf_printk("Odd Index %p \n",(index));
			long success = bpf_map_update_elem(&even, index, &pid, BPF_ANY);
			if(success == 0){
				bpf_printk("\n Success \n");
			}else{
				bpf_printk("\n Failure \n");
			}
			__sync_fetch_and_add((__u32*)index, 1);
		}
	}else{
		index = getIndex(true);
		if(index){
			bpf_printk("Even Index %p \n",(index));
			long success = bpf_map_update_elem(&odd, index, &pid, BPF_ANY);
			if(success == 0){
				bpf_printk("\n Success \n");
			}else{
				bpf_printk("\n Failure \n");
			}
			__sync_fetch_and_add((__u32*)index, 1);
		}

	}
	return 0;
}
