// SPDX-License-Identifier: GPL-2.0
// Memory Snapshot Tool - captures VSZ and RSS on process exec
//
// Hook: tracepoint/sched/sched_process_exec
// Shows: process name, virtual size, anon RSS, file RSS

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MM_FILEPAGES 0
#define MM_ANONPAGES 1
#define MM_SWAPENTS 2
#define MM_SHMEMPAGES 3
#define PAGE_SIZE 4096

// ─── Data structure sent to userspace via ringbuf ───────────────────────────
struct mem_snapshot_event {
u32 pid;
u32 tgid;
char comm[16];

// Virtual memory (pages → bytes)
u64 virt_bytes; // total virtual address space

// Physical memory (RSS)
u64 anon_bytes; // heap + stack
u64 file_bytes; // code + mapped files
u64 swap_bytes; // swapped out
u64 shmem_bytes; // shared memory

// Segment boundaries
u64 heap_start;
u64 heap_end;
u64 heap_size;
u64 stack_start;

};

// ─── Maps ───────────────────────────────────────────────────────────────────
struct {
__uint(type, BPF_MAP_TYPE_RINGBUF);
__uint(max_entries, 1 << 20); // 1MB ringbuf
} events SEC(".maps");

// ─── Helper: read mm_struct fields into event ───────────────────────────────
static __always_inline int read_mm(struct mm_struct *mm,
struct mem_snapshot_event *e)
{
if (!mm)
return -1;

// Virtual size
unsigned long total_vm = BPF_CORE_READ(mm, total_vm);
e->virt_bytes = total_vm * PAGE_SIZE;

// RSS counters
// rss_stat is percpu_counter[4] — access .count (s64) not .counter
e->file_bytes = BPF_CORE_READ(mm, rss_stat[MM_FILEPAGES].count) * PAGE_SIZE;
e->anon_bytes = BPF_CORE_READ(mm, rss_stat[MM_ANONPAGES].count) * PAGE_SIZE;
e->swap_bytes = BPF_CORE_READ(mm, rss_stat[MM_SWAPENTS].count) * PAGE_SIZE;
e->shmem_bytes = BPF_CORE_READ(mm, rss_stat[MM_SHMEMPAGES].count) * PAGE_SIZE;

// Heap boundaries
e->heap_start = BPF_CORE_READ(mm, start_brk);
e->heap_end = BPF_CORE_READ(mm, brk);
e->heap_size = e->heap_end - e->heap_start;

// Stack
e->stack_start = BPF_CORE_READ(mm, start_stack);

return 0;

}

// ─── Tracepoint: fires when any process calls exec ──────────────────────────
/*SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct mem_snapshot_event *e;
	struct task_struct *task;
	struct mm_struct *mm;
	// Reserve space in ringbuf
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
	return 0;
	task = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	mm = BPF_CORE_READ(task, mm);
	if (read_mm(mm, e) < 0) {
	bpf_ringbuf_discard(e, 0);
	return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}*/

struct trace_event_process_exit{
	unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
	char comm[16];
        pid_t pid;
        int prio; 
        bool group_dead;
};

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_process_exit *ctx)
{
	if(!ctx->group_dead){
		return 0;
	}
	bpf_printk("Comm %s \n", ctx->comm);
	struct mem_snapshot_event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
	return 0;
	struct task_struct* task = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	struct mm_struct* mm = BPF_CORE_READ(task, mm);
	if (read_mm(mm, e) < 0) {
	bpf_ringbuf_discard(e, 0);
	return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*SEC("kprobe/exit_mm")
int hook_exit_mm(struct pt_regs *ctx)
{
	bpf_printk("\n hook_exit_mm \n");
	struct mem_snapshot_event *e;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
	return 0;
	struct task_struct* task = (struct task_struct *)bpf_get_current_task();
	e->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	e->tgid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	struct mm_struct* mm = BPF_CORE_READ(task, mm);
	bpf_printk("\n Exit_MM \n");
	if (read_mm(mm, e) < 0) {
	bpf_ringbuf_discard(e, 0);
	return 0;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}*/

char LICENSE[] SEC("license") = "GPL";
