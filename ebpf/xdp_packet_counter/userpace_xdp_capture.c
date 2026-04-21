#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

bool exiting = false;
void capture_signal(){
	exiting = true;
}

struct event {
    __u32 src_ip;
    __u64 count;
};


static void handle_event(void *ctx, int cpu, void *data, __u32 size)
{
    struct event *e = data;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &e->src_ip, ip_str, sizeof(ip_str));
    printf("[cpu %d] src=%s count=%llu\n", cpu, ip_str, e->count);
}

static void handle_lost(void *ctx, int cpu, __u64 lost_cnt)
{
    fprintf(stderr, "[cpu %d] lost %llu events\n", cpu, lost_cnt);
}

int main(){
	struct bpf_object *obj = bpf_object__open_file("counter_packet.bpf.o", 0);
	bpf_object__load(obj);
	struct bpf_program* prog = bpf_object__find_program_by_name(obj, "capture_pkt");
	///////////////
	int ifindex = if_nametoindex("ens7");
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);

	int ifindex6 = if_nametoindex("ens6");
	struct bpf_link *link6 = bpf_program__attach_xdp(prog, ifindex6);

	struct bpf_map *events_map = bpf_object__find_map_by_name(obj, "events");
	struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(events_map), 8,handle_event, handle_lost, NULL, NULL);
	signal(SIGINT, capture_signal);
	while(!exiting){
		int err = perf_buffer__poll(pb, 100 );
        	if (err < 0 ) {
            		fprintf(stderr, "poll error: %d\n", err);
           		 break;
        	}
	}
	///////////////////////////
	perf_buffer__free(pb);
	bpf_link__destroy(link);
	bpf_link__destroy(link6);
	bpf_object__close(obj);
}
