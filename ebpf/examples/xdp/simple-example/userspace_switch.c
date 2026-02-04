#include<stdio.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
//Execute below commands before running this
//sudo ifconfig ens7 mtu 1500 up
//sudo ethtool -L ens7 combined 2
bool exiting = false;
void handle_signal(){
	exiting = true;
}
struct Key{
        __u16 proto;
        __u8 src[6];
};
struct Value{
	__u64 count;
};
static void print_mac(__u16 proto, const unsigned char *m,__u64 count){
        printf("Proto %u Src Mac%02x:%02x:%02x:%02x:%02x:%02x Count %llu \n",proto, m[0],m[1],m[2],m[3],m[4],m[5], count);
}
int main(){
	const char ifname[] = "ens7";
	char obj_path[] = "/home/ubuntu/various-projects/ebpf/examples/xdp/xdp-switch/hello.bpf.o";
	signal(SIGINT, handle_signal);
	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	struct bpf_program *prog = bpf_object__find_program_by_name(obj, "capture_pkt");
	bpf_object__load(obj);

	int ifindex = if_nametoindex(ifname);
	printf("IfIndex == %d %p \n",ifindex, prog);
	struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
	struct bpf_map *hmap = bpf_object__find_map_by_name(obj,"hmap");
	int map_fd = bpf_map__fd(hmap);
	struct Key next_key, key;
	while(!exiting){

	if (bpf_map__get_next_key(hmap, NULL, &next_key,sizeof(struct Key)) == 0) {
    		do {
			struct Value value;
        		// Fetch the value for the current key
        		bpf_map__lookup_elem(hmap, &next_key,sizeof(struct Key), &value, sizeof(struct Value),0);
			print_mac(next_key.proto, next_key.src, value.count);
        		// Move to the next key
        		key = next_key;
    		} while (bpf_map__get_next_key(hmap, &key, &next_key,sizeof(struct Key)) == 0);
	}
		sleep(5);
	}
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
