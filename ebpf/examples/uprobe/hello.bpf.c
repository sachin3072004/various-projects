#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define TASK_COMM_LEN 16
#define MAX_LINE_SIZE 80

// SEC annotation specifies this is a uretprobe attached to the readline function
// in the /bin/bash executable.
SEC("uretprobe//bin/bash:readline")
int BPF_KRETPROBE(printret, const void *ret) {
    char str[MAX_LINE_SIZE];
    char comm[TASK_COMM_LEN];
    u32 pid;

    if (!ret)
        return 0;

    bpf_get_current_comm(&comm, sizeof(comm)); // Get current command name
    pid = bpf_get_current_pid_tgid() >> 32;    // Get PID

    // Read the user-space string from the return value pointer
    bpf_probe_read_user_str(str, sizeof(str), ret);

    // Print the captured data to the BPF trace pipe
    bpf_printk("PID %d (%s) read: %s\n", pid, comm, str);

    return 0;
};

/*SEC("uprobe//home/ubuntu/ebpf/example-1/target:target_add")
int BPF_PROG1(handle_target_add, int a, int b)
{
    bpf_printk("uprobed_add ENTRY: a=%d b=%d\n", a, b);
    return 0;
}*/

//SEC("uprobe/target_add")
SEC("uprobe//home/ubuntu/ebpf/example-1/target:target_add")
int BPF_PROG(handle_target_add, int a, int b)
{
    bpf_printk("uprobed_add ENTRY: a \n");
    return 0;
}

/*SEC("uretprobe//home/ubuntu/ebpf/example-1/target:target_add")
int BPF_PROG2(struct pt_regs *ctx)
{
    bpf_printk("uprobed_add EXIT: ret=%d\n", ret);
    return 0;
}*/

char LICENSE[] SEC("license") = "GPL";

