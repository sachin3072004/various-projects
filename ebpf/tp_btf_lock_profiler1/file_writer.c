#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#define BUF_SIZE 4096
#define THREAD_NUM 40
#define iteration 5000
#define TARGET_FILE "/tmp/target_file.txt"
char BUF[BUF_SIZE];

void* write_to_file(void* n){
	int num = *(int*)n;
	int fd = open(TARGET_FILE, O_WRONLY | O_CREAT | O_TRUNC , 0644);
	char remain = num % 26;
	memset(BUF, 'A' + remain, BUF_SIZE);
	for(int i = 0;i<iteration;i++){
		write(fd, BUF, sizeof(BUF));
		fsync(fd);
	}
	close(fd);
	return NULL;
}


void* read_stats_file(){
	struct stat st;
	for(int i = 0;i<iteration*10;i++){
		stat(TARGET_FILE, &st);
	}
	return NULL;
}

int main(){
	int fd = open(TARGET_FILE, O_WRONLY | O_CREAT | O_TRUNC , 0644);
	close(fd);
	pthread_t thread1[THREAD_NUM];
	pthread_t thread2[THREAD_NUM];
	for(int i = 0;i<THREAD_NUM;i++){
		pthread_create(&thread1[i], NULL, write_to_file, &i);
	}
	for(int i = 0;i<THREAD_NUM;i++){
		pthread_create(&thread1[i], NULL, read_stats_file, NULL);
	}
	for(int i = 0; i < THREAD_NUM; i++){
		pthread_join(thread1[i], NULL);
	}
	for(int i = 0; i < THREAD_NUM; i++){
		pthread_join(thread2[i], NULL);
	}
	unlink(TARGET_FILE);
}
