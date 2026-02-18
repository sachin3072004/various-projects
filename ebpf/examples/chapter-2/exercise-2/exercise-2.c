#include <stdio.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <unistd.h>

void* show_stats(){
	while(1){
		sleep(5);
	}
	return NULL;
}

int main(){
	struct bpf_object* obj = bpf_object__open_file("syscall.bpf.o",0);
	bpf_object__load(obj);
	struct bpf_program* openat = bpf_object__find_program_by_name(obj, "enter_openat2");
	struct bpf_link *link2 = bpf_program__attach(openat);
	struct bpf_map* hmap = bpf_object__find_map_by_name(obj, "hmap");
	pthread_t thread;
	pthread_create(&thread, NULL, show_stats, NULL);
	pthread_join(thread, NULL);
	bpf_object__close(obj);
}
