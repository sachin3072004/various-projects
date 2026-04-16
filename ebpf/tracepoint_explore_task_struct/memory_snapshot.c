// memory_snapshot.c — userspace loader + printer
//
// Build:
// clang -O2 -o memory_snapshot memory_snapshot.c
// -lbpf -lelf -lz
//
// Run:
// sudo ./memory_snapshot

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "memory_snapshot.skel.h"

#define MB(x) ((x) / 1024.0 / 1024.0)

// Must match kernel struct
struct mem_snapshot_event {
unsigned int pid;
unsigned int tgid;
char comm[16];
unsigned long long virt_bytes;
unsigned long long anon_bytes;
unsigned long long file_bytes;
unsigned long long swap_bytes;
unsigned long long shmem_bytes;
unsigned long long heap_start;
unsigned long long heap_end;
unsigned long long heap_size;
unsigned long long stack_start;
};

static volatile int running = 1;

static void sig_handler(int sig) { running = 0; }

// ─── Ringbuf callback: called for every event ────────────────────────────────
static int handle_event(void *ctx, void *data, size_t sz)
{
struct mem_snapshot_event *e = data;

printf("\n┌─── Memory Snapshot ─────────────────────────────────┐\n");
printf("│ Process : %-16s PID: %-6u TGID: %-6u │\n",
e->comm, e->pid, e->tgid);
printf("├─────────────────────────────────────────────────────┤\n");
printf("│ Virtual Memory (VSZ) : %10.2f MB │\n",
MB(e->virt_bytes));
printf("├─── RSS Breakdown ───────────────────────────────────┤\n");
printf("│ Anonymous (heap/stack): %10.2f MB │\n",
MB(e->anon_bytes));
printf("│ File-backed (code/libs): %10.2f MB │\n",
MB(e->file_bytes));
printf("│ Swap : %10.2f MB │\n",
MB(e->swap_bytes));
printf("│ Shared memory : %10.2f MB │\n",
MB(e->shmem_bytes));
printf("├─── Segment Addresses ───────────────────────────────┤\n");
printf("│ Heap : 0x%llx → 0x%llx (%llu KB) │\n",
e->heap_start, e->heap_end, e->heap_size / 1024);
printf("│ Stack : starts at 0x%llx │\n",
e->stack_start);
printf("└─────────────────────────────────────────────────────┘\n");

return 0;

}

int main(void)
{
struct memory_snapshot_bpf *skel;
struct ring_buffer *rb;
int err;

signal(SIGINT, sig_handler);
signal(SIGTERM, sig_handler);

// Load and verify BPF program
skel = memory_snapshot_bpf__open_and_load();
if (!skel) {
fprintf(stderr, "Failed to open BPF skeleton\n");
return 1;
}

// Attach tracepoint
err = memory_snapshot_bpf__attach(skel);
if (err) {
fprintf(stderr, "Failed to attach BPF program\n");
goto cleanup;
}

// Set up ring buffer polling
rb = ring_buffer__new(bpf_map__fd(skel->maps.events),
handle_event, NULL, NULL);
if (!rb) {
fprintf(stderr, "Failed to create ring buffer\n");
goto cleanup;
}

printf("Memory Snapshot Tool running... (Ctrl+C to stop)\n");
printf("Waiting for exec() calls...\n\n");

while (running) {
err = ring_buffer__poll(rb, 100 /* ms */);
if (err == -EINTR) break;
if (err < 0) {
fprintf(stderr, "Ring buffer poll error: %d\n", err);
break;
}
}

ring_buffer__free(rb);

cleanup:
memory_snapshot_bpf__destroy(skel);
return err < 0 ? 1 : 0;
}
