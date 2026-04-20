//SIGBUS, SGUSR1, SIGUSR2, SIGTERM are catchable signals
//SIGKILL,SIGSTOP is not catchable signal
#include <stdio.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>


pthread_t thread_id;
bool running = true;
void signal_handler(){
	running = false;
	printf("Signal handled by %ld\n", pthread_self());
}


void* create_thread1(void*){
	thread_id = pthread_self();
	printf("Thread1 Id %ld\n", thread_id);
	while(running){
	}
	return NULL;
}

void* create_thread2(void*){
	printf("Thread2 Id %ld\n", pthread_self());
	pthread_kill(thread_id, SIGUSR1);
}

int main(){
	struct sigaction sa;
	sa.sa_handler = signal_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	sigaction(SIGUSR1, &sa, NULL);
	pthread_t thread1;
	pthread_t thread2;
	pthread_create(&thread1, NULL, create_thread1, NULL);
	sleep(1);
	pthread_create(&thread2, NULL, create_thread2, NULL);
	pthread_join(thread1, NULL);
	pthread_join(thread2, NULL);

}
