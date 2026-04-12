#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#define TCP_PROTOCOL 6
char license1[] SEC("license") = "GPL";

#define TCP_PROTOCOL    6
#define TCP_ESTABLISHED 1
#define TCP_SYN_RECV    3

struct TCP_CONNECTOR {
	__u16 common_type;
        __u8 common_flags;
        __u8 common_preempt_count;
        __s32 common_pid;       
	const void * skaddr;
        __u32 oldstate; 
        __u32 newstate;
        __u16 sport;
        __u16 dport;
        __u16 family; 
        __u16 protocol;
        __u8 saddr[4];
        __u8 daddr[4];
        __u8 saddr_v6[16];
        __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct Tcp_Events {
	__u16 sport;
	__u16 dport;
	__u8 saddr[4];
	__u8 daddr[4];
};

SEC("tracepoint/sock/inet_sock_set_state")
int handle_tcp_socket_connection(struct TCP_CONNECTOR *ctx){
    	if(ctx->protocol != TCP_PROTOCOL){
		bpf_printk("Proto %d\n", ctx->protocol);
		return 0;
	}
	if (ctx->oldstate != TCP_SYN_RECV && ctx->newstate != TCP_ESTABLISHED)
	{
		bpf_printk("OLDState %d New State %d \n", ctx->oldstate, ctx->newstate);
        	return 0;
	}
	struct Tcp_Events *e = bpf_ringbuf_reserve(&events, sizeof(struct Tcp_Events), 0);
	if (!e) return 0;
	e->sport = ctx->sport;
	e->dport = ctx->dport;
	__builtin_memcpy(e->saddr, ctx->saddr, 4);
	__builtin_memcpy(e->daddr, ctx->daddr, 4);
	bpf_printk("SPort %d DPort %d\n", e->sport, e->dport);
	bpf_ringbuf_submit(e, 0);
    	return 0;
}
