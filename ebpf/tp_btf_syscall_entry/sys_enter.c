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
	struct bpf_object *obj = bpf_object__open_file("tp_btf_sys_call.bpf.o",NULL);
	if(!obj){
		printf("OBJ \n");
	}
	bpf_object__load(obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "prog");
	if(!obj){
		printf("OBJ \n");
	}
	struct bpf_link* link = bpf_program__attach(prog);
	while (running)
        sleep(1);
	printf("\ncleaning up\n");
    	bpf_link__destroy(link);   /* detaches the tracepoint */
    	bpf_object__close(obj);
}
