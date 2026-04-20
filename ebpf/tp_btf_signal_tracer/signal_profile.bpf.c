#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char l1[] SEC("license") = "GPL";

SEC("tp_btf/signal_generate")
int BPF_PROG(on_signal_generate, int sig, struct kernel_siginfo *info, 
						struct task_struct *task,
						int group, int result){
	if(sig != 10){
		return 0;
	}
	__u64 sender_id = bpf_get_current_pid_tgid();
	__u32 sender_tgid = sender_id >> 32;
	__u32 sender_pid = sender_id & 0xFFFFFFFF;
	bpf_printk("SIG  ==== %d\n", sig);
	char comm[TASK_COMM_LEN];  // TASK_COMM_LEN = 16
	bpf_get_current_comm(&comm, sizeof(comm));
	__u32 recv_tgid = BPF_CORE_READ(task, tgid);
	__u32 recv_pid = BPF_CORE_READ(task, pid);
	bpf_printk("SIG  ==== %d Sender %d Receiver %d\n", sig, sender_pid, recv_pid);
	return 0;
}
