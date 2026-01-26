#include "hello.skel.h"
#include <stdio.h>
#include <signal.h> 
#include <unistd.h>

bool exiting = false;
void handle_signal(){
	exiting = true;
}
int main(){
	struct hello_bpf* skel = hello_bpf__open();
	hello_bpf__load(skel);
	hello_bpf__attach(skel);
	while(!exiting){
		sleep(5);
	}
	signal(SIGINT, handle_signal);
	hello_bpf__destroy(skel);
}
