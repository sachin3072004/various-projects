#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char l1[] SEC("license") = "GPL";
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execeve(void* ctx){
	bpf_printk("Hello World");
	return 0;
}
