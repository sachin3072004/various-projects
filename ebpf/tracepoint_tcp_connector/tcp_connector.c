#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <stdlib.h>

static volatile int running = 1;

static void handle_sig(int sig)
{
    running = 0;
}

struct Tcp_Events {
        __u16 sport;
        __u16 dport;
        __u8 saddr[4];
        __u8 daddr[4];
};

static int handle_event(void *ctx, void *data, size_t size)
{
    struct Tcp_Events *e = data;

    printf("sport=%d dport=%d saddr=%d.%d.%d.%d daddr=%d.%d.%d.%d\n",
        e->sport, e->dport,
        e->saddr[0], e->saddr[1], e->saddr[2], e->saddr[3],
        e->daddr[0], e->daddr[1], e->daddr[2], e->daddr[3]);

    return 0;
}

int main(){
	struct bpf_object *obj = bpf_object__open_file("tcp_connector.bpf.o",NULL);
	if(!obj){
		printf("OBJ \n");
	}
	bpf_object__load(obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "handle_tcp_socket_connection");
	if(!obj){
		printf("OBJ \n");
	}
	struct bpf_link* link = bpf_program__attach(prog);
	struct bpf_map* map = bpf_object__find_map_by_name(obj, "events");
	if(!map){
		printf("BPF_MAP\n");
		return 0;
	}
	struct ring_buffer* rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL,NULL);

	while (running){
		int err = ring_buffer__poll(rb, 100);
		if(err <0){
			printf("Poll Error\n");
			break;
		}
	}
	printf("\ncleaning up\n");
    	bpf_link__destroy(link);   /* detaches the tracepoint */
    	bpf_object__close(obj);
}
