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

int main(){
	struct bpf_object *obj = bpf_object__open_file("lock_profiler.bpf.o",NULL);
	if(!obj){
		printf("OBJ \n");
	}
	bpf_object__load(obj);
	struct bpf_program *prog1 = bpf_object__find_program_by_name(obj, "on_contention_begin");
	if(!obj){
		printf("OBJ \n");
	}
	struct bpf_link* link1 = bpf_program__attach(prog1);
	struct bpf_program *prog2 = bpf_object__find_program_by_name(obj, "on_contention_end");
	if(!obj){
		printf("OBJ \n");
	}
	struct bpf_link* link2 = bpf_program__attach(prog2);
	while (running)
        sleep(1);
	printf("\ncleaning up\n");
    	bpf_link__destroy(link1);   /* detaches the tracepoint */
    	bpf_link__destroy(link2);   /* detaches the tracepoint */
    	bpf_object__close(obj);
}
