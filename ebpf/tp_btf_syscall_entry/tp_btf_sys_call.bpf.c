#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char l1[] SEC("license") = "GPL";

SEC("tp_btf/sys_enter")
int BPF_PROG(prog, struct pt_regs *arg2, long int arg3){
	const char* fileName = (const char*)PT_REGS_PARM1(arg2);
	char buf[100];
	int len = bpf_probe_read_user_str(buf, 100, fileName);	
	if(len == 8 ){ //it is reading test.txt given in the test.c
		bpf_printk("Read User Str %s Len %d \n", buf, len);
	}
	return 0;
}
