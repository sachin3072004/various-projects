#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

struct MAP_FD{
	int odd;
	int even;
	int index;
};

void* print_map(void* mfd){
	struct MAP_FD *mfdPtr = (struct MAP_FD*)mfd;
	while(1){
		unsigned int current_key = -1;
		unsigned int next_key = -1;
		int odd_key = 0;
		int odd_val = 0;
		int odd_index = bpf_map_lookup_elem(mfdPtr->index, &odd_key, &odd_val);
		printf("Odd_Index %d %d \n", odd_index, odd_val);
		int even_key = 1;
		int even_val = 0;
		int even_index = bpf_map_lookup_elem(mfdPtr->index, &even_key, &even_val);
		printf("Even_Index %d %d\n", even_index, even_val);
		int count = 0;
		while(bpf_map_get_next_key(mfdPtr->odd,&current_key,&next_key) == 0 && count < odd_val){
			unsigned long long val = 0;
			if(bpf_map_lookup_elem(mfdPtr->odd, &next_key, &val) == 0) {
				printf("Odd Key: %u, Value: %lld\n", next_key, val);
			}
			current_key = next_key;
			count += 1;
		}
		current_key = -1;
		next_key = -1;
		count = 0;
		while(bpf_map_get_next_key(mfdPtr->even,&current_key,&next_key) == 0 && count < even_val){
			unsigned long long val = 0;
			if(bpf_map_lookup_elem(mfdPtr->odd, &next_key, &val) == 0) {
				printf("Even Key: %u, Value: %lld\n", next_key, val);
			}
			current_key = next_key;
			count += 1;
		}
		sleep(5);
	}
	return NULL;
}

int main(){
	struct bpf_object* bpf_obj = bpf_object__open_file("exercise-1.bpf.o",0);
	bpf_object__load(bpf_obj);
	struct bpf_program *prog = bpf_object__find_program_by_name(bpf_obj, "trace_point_execve");
	struct bpf_link *link = bpf_program__attach(prog);
    	if (!link) {
        	fprintf(stderr, "Failed to attach program\n");
        	return 1;
    	}
	struct bpf_map *odd =  bpf_object__find_map_by_name(bpf_obj, "odd");
	int odd_fd = bpf_map__fd(odd);
	struct bpf_map *even =  bpf_object__find_map_by_name(bpf_obj, "even");
	int even_fd = bpf_map__fd(even);
	struct bpf_map *index =  bpf_object__find_map_by_name(bpf_obj, "meta_map");
	int index_fd = bpf_map__fd(index);
	struct MAP_FD mfd;
	mfd.odd = odd_fd;
	mfd.even = even_fd;
	mfd.index = index_fd;
	pthread_t pid;
	pthread_create(&pid, NULL, print_map, (void*)&mfd);
	pthread_join(pid, NULL);
	bpf_object__close(bpf_obj);
}
