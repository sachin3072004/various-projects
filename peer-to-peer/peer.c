#include <stdio.h>
#include <pthread.h>
#include "common.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#define randomIdLen 20
FILE *fp;
char logFileName[100] = {'\0'};
int TIME_OUT = 10;
pthread_mutex_t file_lock;
pthread_mutex_t checkPeerConnectionsLock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t checkPeerConnectionsCond = PTHREAD_COND_INITIALIZER;
bool checkPeerConnections = true;
int numAttempts = 5;
int BUF_SIZE = 2000;
int KEEP_ALIVE = 5;
enum MSGTYPE{
        REQUEST = 0,
        RESPONSE = 1,
	INTRO = 2,
	KEEPALIVE = 3
};

enum CMD {
        RM,
        LS,
        SIZE,
        DOWNLOAD,
        NO_CMD,
};

typedef struct {
        enum MSGTYPE msgType;
        int idLen;
        int ipAddressLen;
        char ipAddress[15];
        int portLen;
        char port[5];
        char id[20];
        enum CMD cmd;
        int payloadLen;
        char payload[1000];
        uint8_t complete;
}Msg;

char randomId[randomIdLen] ;
pthread_mutex_t randomIdLock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t randomIdCond = PTHREAD_COND_INITIALIZER;
void* generate_id(){
	randomId[0] = '1';
	randomId[1] = '\0';
	while(1){
		pthread_mutex_lock(&randomIdLock);
		while(strlen(randomId) != 0){
			pthread_cond_wait(&randomIdCond, &randomIdLock);
		}
		srand(time(NULL));
    		int randomIdNum = rand();
		itoa(randomIdNum, randomId);
		pthread_cond_signal(&randomIdCond);
		pthread_mutex_unlock(&randomIdLock);
	}
}

void print_qm(Msg* qm){
        printf("MSGTYPE %d \n",qm->msgType);
        printf("IDLEN %d \n",qm->idLen);
        printf("ipAddressLen %d \n",qm->ipAddressLen);
        char ipAddress[20] = {'\0'};
        strncpy(ipAddress, qm->ipAddress, qm->ipAddressLen);
        printf("ipAddress %s \n",ipAddress);
        printf("portLen %d \n",qm->portLen);
        char port[5] = {'\0'};
        strncpy(port, qm->port, qm->portLen);
        printf("port %s \n",port);
        char id[5] = {'\0'};
        strncpy(id, qm->id, qm->idLen);
        printf("id %s \n",qm->id);
        printf("CMD %d \n",qm->cmd);
        char payload[1000] = {'\0'};
        printf("PayLoadLen %d \n",qm->payloadLen);
        strncpy(payload, qm->payload, qm->payloadLen);
        printf("PayLoad %s \n",qm->payload);
        printf("Complete %d \n",qm->complete);
}

static void write_u32_be(uint8_t *buf, uint32_t v) {
        buf[0] = (v >> 24) & 0xFF;
        buf[1] = (v >> 16) & 0xFF;
        buf[2] = (v >> 8) & 0xFF;
        buf[3] = v & 0xFF;
}

size_t serialize_query(Msg *msg, uint8_t *buf, size_t bufsize)
{
        uint8_t *p = buf;
        uint8_t *end = buf + bufsize;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->msgType); p += 4;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->idLen); p += 4;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->ipAddressLen); p += 4;

        if (p + msg->ipAddressLen > end) return 0;
        memcpy(p, msg->ipAddress, msg->ipAddressLen);
        p += msg->ipAddressLen;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->portLen); p += 4;

        if (p + msg->portLen > end) return 0;
        memcpy(p, msg->port, msg->portLen);
        p += msg->portLen;

        if (p + msg->idLen > end) return 0;
        memcpy(p, msg->id, msg->idLen);
        p += msg->idLen;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->cmd); p += 4;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->payloadLen); p += 4;

        if (p + msg->payloadLen > end) return 0;
        memcpy(p, msg->payload, msg->payloadLen);
        p += msg->payloadLen;

        memcpy(p, &msg->complete, 1);
        p += 1;
        return (size_t)(p - buf);
}

static uint32_t read_u32_be(const uint8_t *buf) {
        return ((uint32_t)buf[0] << 24) |
        ((uint32_t)buf[1] << 16) |
        ((uint32_t)buf[2] << 8) |
        (uint32_t)buf[3];
}

int deserialize_query(Msg *msg, const uint8_t *buf, size_t len)
{
        const uint8_t *p = buf;
        const uint8_t *end = buf + len;

        if (p + 4 > end) return -1;
        msg->msgType = (enum MSGTYPE)read_u32_be(p); p += 4;

        if (p + 4 > end) return -1;
        msg->idLen = (int)read_u32_be(p); p += 4;
        if (msg->idLen < 0 || msg->idLen > (int)sizeof msg->id) return -1;

        if (p + 4 > end) return -1;
        msg->ipAddressLen = (int)read_u32_be(p); p += 4;
        if (msg->ipAddressLen < 0 || msg->ipAddressLen > (int)sizeof msg->ipAddress) return -1;

        if (p + msg->ipAddressLen > end) return -1;
        memcpy(msg->ipAddress, p, msg->ipAddressLen);
        p += msg->ipAddressLen;

        if (p + 4 > end) return -1;
        msg->portLen = (int)read_u32_be(p); p += 4;
        if (msg->portLen < 0 || msg->portLen > (int)sizeof msg->port) return -1;

        if (p + msg->portLen > end) return -1;
        memcpy(msg->port, p, msg->portLen);
        p += msg->portLen;

        if (p + msg->idLen > end) return -1;
        memcpy(msg->id, p, msg->idLen);
        p += msg->idLen;

        if (p + 4 > end) return -1;
        msg->cmd = (enum CMD)read_u32_be(p); p += 4;
        printf("MSG CMD = %d \n", msg->cmd);
        if (p + 4 > end) return -1;
        msg->payloadLen = (int)read_u32_be(p); p += 4;
        if (msg->payloadLen < 0 || msg->payloadLen > (int)sizeof msg->payload) return -1;

        if (p + msg->payloadLen > end) return -1;
        memcpy(msg->payload, p, msg->payloadLen);
        p += msg->payloadLen;

        memcpy(&msg->complete, p, 1);
        p += 1;
        return (int)(p - buf);
}

void write_to_log(char* ptr){
	pthread_mutex_lock(&file_lock);
	FILE* fp = fopen(logFileName, "a");
	int sizeOfElement = 1;
	if(fp){
		fwrite(ptr, sizeOfElement, strlen(ptr), fp);
		fflush(fp);
	}else {
		printf("File Not open\n");
	}
	fclose(fp);
	pthread_mutex_unlock(&file_lock);
}

void read_from_socket(int sock_fd, Msg** q, int *len){
	int count = 0;;
        char buf[BUF_SIZE];
	int n = read(sock_fd, buf, sizeof(buf) - 1);
	printf("Read N %d %c \n",n,*buf);
	if (n < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}
	if(n == 0){
		char msg[100] = "Nothing To Read \n";
		write_to_log(msg);
		*len = 0;
		return;
	}
	buf[n] = '\0';
	int parsedLen = 0;
	printf("Char == %c\n", *(buf + parsedLen));
	while(parsedLen != n){
		printf("Entered here");
		Msg *qm = malloc(sizeof(Msg));
		parsedLen += deserialize_query(qm, (uint8_t*)buf + parsedLen, 2000);
		printf("ParsedLen == %d \n", parsedLen);
		*q = realloc(*q, count + 1 * sizeof(Msg));
		(*q)[count] = *qm;
		count += 1;
		*len = count;
		free(qm);
		if((*q)[count-1].complete){
			return;
		}
	}
}

void printLL(){
        Peer* p = head;
        while(p){
                char buffer[200] = {'\0'};
                snprintf(buffer, sizeof(buffer), "Peer IP: %s Peer Port: %d Socket %d \n", p->ip,p->port, p->sockfd);
                write_to_log(buffer);
                p = p->next;
        }
}

void* start_server(){
	int listen_fd, conn_fd;
        struct sockaddr_in addr;
        listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (listen_fd < 0) {
                perror("socket");
                exit(EXIT_FAILURE);
        }

        int opt = 1;
        if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                perror("setsockopt");
                exit(EXIT_FAILURE);
        }

        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(serverPort);

        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                perror("bind");
                exit(EXIT_FAILURE);
        }

        if (listen(listen_fd, 5) < 0) {
                perror("listen");
                exit(EXIT_FAILURE);
        }
	for(;;){
		struct sockaddr_in client;
		socklen_t clilen = sizeof(client);
		conn_fd = accept(listen_fd, (struct sockaddr*)&client, &clilen);
		if (conn_fd < 0) {
			perror("accept");
			exit(EXIT_FAILURE);
		}
		Msg* q = NULL;
		int len = 0;
		read_from_socket(conn_fd, &q, &len);
		printf("Pointer %p Len %d\n",q, len);
		Peer* temp = head;
		//print_qm(q);
		while(temp){
			if(!strcmp(temp->ip, q[0].ipAddress) && temp->port == atoi(q[0].port)){
				pthread_rwlock_wrlock(&temp->lock);
				temp->sockfd = conn_fd;
				pthread_rwlock_unlock(&temp->lock);
				break;
			}
			temp = temp->next;
		}

	}
}

bool received_ttl_msg = false;
pthread_cond_t ttlCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t ttlMutex = PTHREAD_MUTEX_INITIALIZER;
void* check_ttl(void* threadId){
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	pthread_t parentThread = *(pthread_t*)threadId;
	long int last = ts.tv_sec;
	while(1){
		pthread_mutex_lock(&ttlMutex);
		while(received_ttl_msg == false){
			ts.tv_sec += 5;
			int ret = pthread_cond_timedwait(&ttlCond, &ttlMutex,&ts);
			struct timespec current;
			clock_gettime(CLOCK_REALTIME, &current);
			if(ret == ETIMEDOUT && current.tv_sec - last > TIME_OUT){
				Peer* temp = head;
				while(temp){
					char msg[200];
					snprintf(msg, sizeof(msg), "Neighbor's IP  %s Port %d SockFd %d \n",temp->ip, temp->port, temp->sockfd);
					write_to_log(msg);
					temp = temp->next;
				}
				temp = head;
				while(temp){
					pthread_rwlock_rdlock(&temp->lock);
					if(parentThread  == temp->thread && temp->sockfd != -1){
						char msg[200] = {'\0'};
					       	snprintf(msg, sizeof(msg), "Last keepalive packet arrived %ld Current Time %ld \n",last, current.tv_sec);
						write_to_log(msg);
						memset(msg, 0, sizeof(msg));
					       	snprintf(msg, sizeof(msg), "Dead Neighbor's IP  %s Port %d SockFd %d \n",temp->ip, temp->port, temp->sockfd);
						write_to_log(msg);
						pthread_rwlock_unlock(&temp->lock);
						pthread_rwlock_wrlock(&temp->lock);
						temp->sockfd = -1;
						pthread_rwlock_unlock(&temp->lock);
						memset(msg, 0, sizeof(msg));
					       	snprintf(msg, sizeof(msg), "Dead Neighbor's New State IP  %s Port %d SockFd %d \n",temp->ip, temp->port, temp->sockfd);
						write_to_log(msg);
						break;

					}
					pthread_rwlock_unlock(&temp->lock);
					temp = temp->next;
				}
				pthread_mutex_unlock(&ttlMutex);
				pthread_cancel(parentThread);
				return NULL;
			}else if(received_ttl_msg == true){
				received_ttl_msg = false;
				clock_gettime(CLOCK_REALTIME, &ts);
				last = ts.tv_sec;
			}
		}
		pthread_mutex_unlock(&ttlMutex);
	}	
}

void* handle_received_msgs(void* node){
	Peer p = *(Peer*)node;
	pthread_t checkTTL = 100;
	pthread_create(&checkTTL, NULL, check_ttl, &p.thread);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	while(1){
		Msg* q = NULL;
		int len = 0;
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(p.sockfd, &rfds);
		struct timeval tv;
		tv.tv_sec  = 5;
		tv.tv_usec = 0;
		int r = select(p.sockfd + 1, &rfds, NULL, NULL, &tv);
		if (r == 0) {
			char msg[100];
			snprintf(msg, sizeof(msg),"Thread is cancelled %d\n",serverPort);
			pthread_testcancel();
		} else if (r > 0) {
			read_from_socket(p.sockfd, &q, &len);
			if(len == 0){
				Peer* temp = head;
				while(temp){
					if(!strcmp(temp->ip, p.ip) && temp->port == p.port){
						char msg[200];
						snprintf(msg, sizeof(msg),"Connection Closed by remote ip %s port %d \n", temp->ip, temp->port);
						write_to_log(msg);
						pthread_rwlock_wrlock(&temp->lock);
						temp->sockfd = -1;
						pthread_rwlock_unlock(&temp->lock);
						return NULL;
					}
					temp = temp->next;
				}
			}
			if(q && q->msgType == KEEPALIVE){
				char msgStr[200] = {'\0'};
				snprintf(msgStr, sizeof(msgStr), "\n KeepAlive Received From IP %s Port %s \n", q->ipAddress, q->port);
				write_to_log(msgStr);
				pthread_mutex_lock(&ttlMutex);
				received_ttl_msg = true;
				pthread_cond_signal(&ttlCond);
				pthread_mutex_unlock(&ttlMutex);

			}
		}

	}
	return NULL;
}

void* send_ttl(){
	int count = 0;
	while(1){
		Peer* temp = head;
		while(temp){
			pthread_rwlock_rdlock(&temp->lock);
			if(temp->sockfd != -1){
				Msg msg;
				msg.msgType = KEEPALIVE;
				msg.ipAddressLen = strlen(serverIP);
				strcpy(msg.ipAddress, serverIP);
				char portStr[10];
				itoa(serverPort, portStr);
				msg.portLen = strlen(portStr);
				msg.idLen = 0;
				strcpy(msg.port,portStr) ;
				msg.complete = true;
				printf("Keepalive MSG Sent \n");
				//print_qm(&msg);
				uint8_t buf1[BUF_SIZE];
				int len = serialize_query(&msg, buf1, BUF_SIZE);
				char msgStr[200] = {'\0'};
				snprintf(msgStr, sizeof(msgStr), "\n KeepAlive Sent To %s Port %d \n", temp->ip, temp->port);
				write_to_log(msgStr);
				if(serverPort == 8081 && count < 3){
					write(temp->sockfd, buf1, len);
				}
				count += 1;
			}
			pthread_rwlock_unlock(&temp->lock);
			temp = temp->next;
		}
		sleep(KEEP_ALIVE);
	}
	return NULL;
}

void* start_connections_with_peers(){
	while(1){
		pthread_mutex_lock(&checkPeerConnectionsLock);
		int* attempts = calloc(sizeof(uint8_t), totalNeighbors);
		int connectionsMade = 0;
		do {
			int neighbor = 0;
			Peer* temp = head;
			connectionsMade = 0;
			while(temp){
				if(attempts[neighbor] < numAttempts && (temp->sockfd == -1) && (strcmp(temp->ip, serverIP)|| temp->port > serverPort)){
					attempts[neighbor] += 1;
					int sock_fd;
					struct sockaddr_in addr;
					sock_fd = socket(AF_INET, SOCK_STREAM, 0);
					if (sock_fd < 0) {
						perror("socket");
						exit(EXIT_FAILURE);
					}

					memset(&addr, 0, sizeof(addr));
					addr.sin_family = AF_INET;
					addr.sin_port = htons(temp->port);

					if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
						perror("inet_pton");
					}
					int result = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
				       	if(result < 0) {
						char msgStr[200] = {'\0'};
						snprintf(msgStr, sizeof(msgStr), "\n Connection Rejected by IP %s Port %d\n", temp->ip, temp->port);
						write_to_log(msgStr);
					}else{
						char msgStr[200] = {'\0'};
						snprintf(msgStr, sizeof(msgStr), "\n Connection Accepted by IP %s Port %d\n", temp->ip, temp->port);
						write_to_log(msgStr);
						pthread_rwlock_wrlock(&temp->lock);
						temp->sockfd = sock_fd;
						pthread_create(&temp->thread, NULL, handle_received_msgs, temp);
						pthread_rwlock_unlock(&temp->lock);
						connectionsMade += 1;
						pthread_mutex_lock(&randomIdLock);
						memset(randomId, 0, randomIdLen);
						while(strlen(randomId) == 0){
							pthread_cond_signal(&randomIdCond);
							pthread_cond_wait(&randomIdCond, &randomIdLock);
						}
						Msg msg;
 						msg.msgType = INTRO;
        					msg.idLen = strlen(randomId);
        					msg.ipAddressLen = strlen(serverIP);
        					strcpy(msg.ipAddress, serverIP) ;
						char serverPortStr[10];
						itoa(serverPort, serverPortStr);
        					msg.portLen = strlen(serverPortStr);
        					strcpy(msg.port, serverPortStr);
        					strcpy(msg.id, randomId);
						memset(randomId, 0, randomIdLen);
						pthread_mutex_unlock(&randomIdLock);
        					msg.complete = true;
						uint8_t buf1[BUF_SIZE];
					 	int len = serialize_query(&msg, buf1, BUF_SIZE);
						write(sock_fd, buf1, len);

					}
				}else{
					connectionsMade += 1;
				}
				temp = temp->next;
				neighbor += 1;
			}
			if(totalNeighbors != connectionsMade){
				sleep(5);
			}else{
				printf("All connections are made");
			}
		}while(totalNeighbors != connectionsMade);
		free(attempts);
		checkPeerConnections = false;
		if(!checkPeerConnections){
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME, &ts);
			ts.tv_sec += 5;
			pthread_cond_timedwait(&checkPeerConnectionsCond, &checkPeerConnectionsLock, &ts);
		}
		pthread_mutex_unlock(&checkPeerConnectionsLock);
	}
}




void* listNeighbors(){
	Peer* temp = head;
	while(temp){
		pthread_rwlock_rdlock(&temp->lock);
		printf("Neighbor Port %d socket %d \n", temp->port, temp->sockfd);
		Peer* temp1 = temp->next;
		pthread_rwlock_unlock(&temp->lock);
		temp = temp1;
	}
	return NULL;
}

void* prompt(){
	int choice = 0;
	while(1){
		printf("1) LS \n");
		printf("2) RM \n");
		printf("3) DW \n");
		printf("4) Neighbors \n");
		printf("Enter your Choice");
		scanf("%d",&choice);
		char serverIP[100];
		char port[100];
		char fileName[100];
		switch(choice){
			case 1:
				printf("Enter the server ip");
				scanf("%s", serverIP);
				printf("Enter the Port");
				scanf("%s", port);
				break;
			case 2:
				printf("Enter the File Name");
				scanf("%s", fileName);
				break;
			case 3:
				printf("Enter the File Name");
				scanf("%s", fileName);
				break;
			case 4:
				pthread_t t1 = 100;
				pthread_create(&t1, NULL, listNeighbors, NULL);
				pthread_join(t1, NULL);
				break;

		}

	}
}



int main(int argc, char** argv){
	printf("Argc %d %s \n",argc, argv[1]);
	readFile(argv[1]);
	strcpy(logFileName, serverIP);
	char serverHostStr[100] = {'\0'};
	itoa(serverPort, serverHostStr);
	strcpy(logFileName+strlen(serverIP), serverHostStr);
	remove(logFileName);
	pthread_t prompt_t = 1;
	pthread_create(&prompt_t, NULL, prompt,  NULL);
	pthread_t server_t = 2;
	pthread_create(&server_t, NULL, start_server,  NULL);
	pthread_t connect_with_higher_ip_port = 3;
	pthread_create(&connect_with_higher_ip_port, NULL, start_connections_with_peers,  NULL);
	pthread_t generateId = 4;
	pthread_create(&generateId, NULL, generate_id, NULL);
	pthread_t sendTTL = 4;
	pthread_create(&sendTTL, NULL, send_ttl, NULL);
	pthread_join(connect_with_higher_ip_port, NULL);
	pthread_join(prompt_t, NULL);
	pthread_join(generateId, NULL);
}
