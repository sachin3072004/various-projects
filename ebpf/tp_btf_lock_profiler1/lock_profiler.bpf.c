#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char l1[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} record SEC(".maps");


SEC("tp_btf/contention_begin")
int BPF_PROG(on_contention_begin,void* lock, unsigned int result){
	char comm[TASK_COMM_LEN];  // TASK_COMM_LEN = 16
	bpf_get_current_comm(&comm, sizeof(comm));
	if(bpf_strncmp(comm, TASK_COMM_LEN, "file_writer") == 0){
		__u64 pid_tgid =  bpf_get_current_pid_tgid();
		__u32 pid = pid_tgid & 0xFFFFFFFF;
		u64 ts  = bpf_ktime_get_ns();
		bpf_map_update_elem(&record, &pid, &ts, BPF_ANY);
	}
	return 0;
}

SEC("tp_btf/contention_end")
int BPF_PROG(on_contention_end,void* lock, unsigned int result){
	char comm[TASK_COMM_LEN];  // TASK_COMM_LEN = 16
	bpf_get_current_comm(&comm, sizeof(comm));
	if(bpf_strncmp(comm, TASK_COMM_LEN, "file_writer") == 0){
		__u64 pid_tgid =  bpf_get_current_pid_tgid();
		__u32 pid = pid_tgid & 0xFFFFFFFF;
		u64 ts  = bpf_ktime_get_ns();
		void *result = bpf_map_lookup_elem(&record, &pid);
		if(result){
			bpf_printk("Diff: %u \n", ts - *((u64*)(result)));
			bpf_map_delete_elem(&record, &pid);
		}
	}
	return 0;
}
