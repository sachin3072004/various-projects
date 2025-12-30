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
#define IpAddrLen 20
#define PortLen 5
#define PayloadLen 1000
#define IdLen 10
FILE *fp;
char logFileName[100] = {'\0'};
int TIME_OUT = 10;
pthread_mutex_t file_lock;
pthread_mutex_t checkPeerConnectionsLock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t checkPeerConnectionsCond = PTHREAD_COND_INITIALIZER;
void* handle_received_msgs(void* node);
typedef struct Request{
	char id[IdLen];
	char srcIP[IpAddrLen];
	char srcPort[PortLen];
	char originIp[IpAddrLen];
	char originPort[PortLen];
	bool complete;
	struct Request* next;
	pthread_rwlock_t lock;
}Request;

Request *requestHead = NULL;
Request *requestTail = NULL;
pthread_mutex_t requestHeadLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t requestTailLock = PTHREAD_MUTEX_INITIALIZER;

bool checkPeerConnections = true;
int numAttempts = 5;
int BUF_SIZE = 2000;
int KEEP_ALIVE = 5;
enum MSGTYPE{
        REQUEST = 0,
        RESPONSE = 1,
	INTRO = 2,
	KEEPALIVE = 3,
	UNKNOWN = 4,
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
        int originIpLen;
        char originIp[IpAddrLen];
        int originPortLen;
        char originPort[PortLen];
        int srcIpLen;
        char srcIp[IpAddrLen];
        int srcPortLen;
        char srcPort[PortLen];
        int dstIpLen;
        char dstIp[IpAddrLen];
        int dstPortLen;
        char dstPort[PortLen];
        char id[IdLen];
        enum CMD cmd;
        int payloadLen;
        char payload[PayloadLen];
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
	if(qm->cmd != LS){
		return;
	}
        printf("MSGTYPE %d \n",qm->msgType);
        printf("IDLEN %d \n",qm->idLen);
        printf("srcIpAddressLen %d \n",qm->srcIpLen);
        char srcIp[20] = {'\0'};
        strncpy(srcIp, qm->srcIp, qm->srcIpLen);
        printf("srcIpAddress %s \n",qm->srcIp);
        printf("srcIpAddressLen %d \n",qm->srcIpLen);
        printf("srcPort %s \n",qm->srcPort);
        printf("srcPortLen %d \n",qm->srcPortLen);
        printf("dstIpAddress %s \n", qm->dstIp);
        printf("dstIpAddressLen %d \n",qm->dstIpLen);
        printf("dstPort %s \n",qm->dstPort);
        printf("dstPortLen %d \n",qm->dstPortLen);
        printf("originIpAddress %s \n", qm->originIp);
        printf("originIpAddressLen %d \n",qm->originIpLen);
        printf("originPort %s \n",qm->originPort);
        printf("originPortLen %d \n",qm->originPortLen);
        printf("portLen %d \n",qm->srcPortLen);
        char port[5] = {'\0'};
        strncpy(port, qm->srcPort, qm->srcPortLen);
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
        write_u32_be(p, (uint32_t)msg->originIpLen); p += 4;
	printf("OriginIPLen %d \n",msg->originIpLen);
        if (p + msg->originIpLen > end) return 0;
        memcpy(p, msg->originIp, msg->originIpLen);
        p += msg->originIpLen;

	//
        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->originPortLen); p += 4;

        if (p + msg->originPortLen > end) return 0;
        memcpy(p, msg->originPort, msg->originPortLen);
        p += msg->originPortLen;
	//
        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->srcIpLen); p += 4;

        if (p + msg->srcIpLen > end) return 0;
        memcpy(p, msg->srcIp, msg->srcIpLen);
        p += msg->srcIpLen;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->srcPortLen); p += 4;

        if (p + msg->srcPortLen > end) return 0;
        memcpy(p, msg->srcPort, msg->srcPortLen);
        p += msg->srcPortLen;
	//
        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->dstIpLen); p += 4;

        if (p + msg->dstIpLen > end) return 0;
        memcpy(p, msg->dstIp, msg->dstIpLen);
        p += msg->dstIpLen;

        if (p + 4 > end) return 0;
        write_u32_be(p, (uint32_t)msg->dstPortLen); p += 4;

        if (p + msg->dstPortLen > end) return 0;
        memcpy(p, msg->dstPort, msg->dstPortLen);
        p += msg->dstPortLen;
	//
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
	//
        if (p + 4 > end) return -1;
        msg->originIpLen = (int)read_u32_be(p); p += 4;
        if (msg->originIpLen < 0 || msg->originIpLen > (int)sizeof msg->originIp) return -1;

        if (p + msg->originIpLen > end) return -1;
        memcpy(msg->originIp, p, msg->originIpLen);
        p += msg->originIpLen;

        if (p + 4 > end) return -1;
	msg->originPortLen = (int)read_u32_be(p); p += 4;
        if (msg->originPortLen < 0 || msg->originPortLen > (int)sizeof msg->originPort) return -1;

        if (p + msg->originPortLen > end) return -1;
        memcpy(msg->originPort, p, msg->originPortLen);
        p += msg->originPortLen;
	//
        if (p + 4 > end) return -1;
        msg->srcIpLen = (int)read_u32_be(p); p += 4;
        if (msg->srcIpLen < 0 || msg->srcIpLen > (int)sizeof msg->srcIp) return -1;

        if (p + msg->srcIpLen > end) return -1;
        memcpy(msg->srcIp, p, msg->srcIpLen);
        p += msg->srcIpLen;

        if (p + 4 > end) return -1;
        msg->srcPortLen = (int)read_u32_be(p); p += 4;
        if (msg->srcPortLen < 0 || msg->srcPortLen > (int)sizeof msg->srcPort) return -1;

        if (p + msg->srcPortLen > end) return -1;
        memcpy(msg->srcPort, p, msg->srcPortLen);
        p += msg->srcPortLen;
	//
        if (p + 4 > end) return -1;
        msg->dstIpLen = (int)read_u32_be(p); p += 4;
        if (msg->dstIpLen < 0 || msg->dstIpLen > (int)sizeof msg->dstIp) return -1;

        if (p + msg->dstIpLen > end) return -1;
        memcpy(msg->dstIp, p, msg->dstIpLen);
        p += msg->dstIpLen;

        if (p + 4 > end) return -1;
	msg->dstPortLen = (int)read_u32_be(p); p += 4;
        if (msg->dstPortLen < 0 || msg->dstPortLen > (int)sizeof msg->dstPort) return -1;

        if (p + msg->dstPortLen > end) return -1;
        memcpy(msg->dstPort, p, msg->dstPortLen);
        p += msg->dstPortLen;
	//
        if (p + msg->idLen > end) return -1;
        memcpy(msg->id, p, msg->idLen);
        p += msg->idLen;

        if (p + 4 > end) return -1;
        msg->cmd = (enum CMD)read_u32_be(p); p += 4;
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

void read_from_socket(int sock_fd, Msg* q){
        char buf[BUF_SIZE];
	int n = read(sock_fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		perror("read");
		exit(EXIT_FAILURE);
	}
	if(n == 0){
		q->msgType = UNKNOWN;
		char msg[100] = "Nothing To Read \n";
		write_to_log(msg);
		return;
	}
	buf[n] = '\0';
	deserialize_query(q, (uint8_t*)buf , 2000);
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
		Msg* q = malloc(sizeof(Msg));
		q->msgType = UNKNOWN;
		read_from_socket(conn_fd, q);
		Peer* neighborPtr = head;
		//print_qm(q);
		while(neighborPtr){
			if(!strcmp(neighborPtr->ip, q[0].srcIp) && neighborPtr->port == atoi(q[0].srcPort)){
				pthread_rwlock_wrlock(&(neighborPtr->lock));
				neighborPtr->sockfd = conn_fd;
				pthread_create(&(neighborPtr->thread), NULL, handle_received_msgs, neighborPtr);
				pthread_rwlock_unlock(&(neighborPtr->lock));
				break;
			}
			neighborPtr = neighborPtr->next;
		}
		free(q);

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
						//sachin fix it
						//temp->sockfd = -1;
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

bool add_request(Msg *msg){
	Request* temp = requestHead;
	while(temp){
		if(strcmp(temp->id , msg->id) == 0  && (strcmp(temp->originIp, msg->originIp) == 0) && (strcmp(temp->originPort, msg->originPort) == 0)){
			return false;
		}
		temp = temp->next;
	}
	pthread_mutex_lock(&requestTailLock);
	requestTail->next = malloc(sizeof(Request));
	strcpy(requestTail->next->id,msg->id);
	strcpy(requestTail->next->srcIP, msg->srcIp);
	strcpy(requestTail->next->srcPort, msg->srcPort); 
	requestTail->next->complete = true;
	requestTail = requestTail->next;
	pthread_mutex_unlock(&requestTailLock);
	return true;

}

void* request_forwarder(void* msg1){
	printf("\nRequest Forwarder\n");
	print_qm(msg1);
	Msg msg = *(Msg*)msg1;
	Peer* temp = head;
	while(temp){
		printf("Neighbor %s Port %d \n",temp->ip,temp->port);
		pthread_rwlock_rdlock(&temp->lock);
		if(!(strcmp(temp->ip, msg.srcIp) == 0 && temp->port == atoi(msg.srcPort))){
			pthread_rwlock_unlock(&temp->lock);
			pthread_rwlock_wrlock(&temp->lock);
			uint8_t buf1[2000] = {'\0'};
			strcpy(msg.srcIp,serverIP);
			strcpy(msg.srcPort,serverPortStr);
			//strcpy(msg.dstIp,temp->ip);
			print_qm(&msg);
			int len = serialize_query(&msg, buf1, 2000);
			printf("Sending to sockfd: %d Len: %d Neighbor IP%s NeighborPort %d \n", temp->sockfd,len,temp->ip,temp->port);
			write(temp->sockfd, buf1, len);
				
		}
		pthread_rwlock_unlock(&temp->lock);
		temp = temp->next;
	}

	return NULL;
}

void* response_forwarder(void* msg1){
	Msg respMsg  = *(Msg*)msg1;
	Msg *msg = &respMsg;
	Peer* neighborPtr = head;
        while(neighborPtr){
		printf("Neighbor Ptr %s Port %d Msg Src%s Msg Port %s\n",neighborPtr->ip, neighborPtr->port,msg->srcIp, msg->srcPort);
		if(strcmp(neighborPtr->ip, msg->srcIp) == 0 && neighborPtr->port == atoi( msg->srcPort)){
			break;
		}
		neighborPtr = neighborPtr->next;
	}
	printf("Send Response back %p \n", neighborPtr);
	if(msg->msgType == REQUEST){
		if(msg->cmd == LS){
        		FILE *fp = popen("ls -l","r");
			char buf[10] = {'\0'};
			int nread = 0;
			while((nread = fread(buf, 1, sizeof(buf),fp)) > 0){
				Msg qm;
				qm.msgType = RESPONSE;
				qm.idLen = msg->idLen;
				
				qm.srcIpLen = strlen(serverIP);
				strncpy(qm.srcIp, serverIP, qm.srcIpLen);

				qm.originIpLen = strlen(serverIP);
				strncpy(qm.originIp, serverIP, qm.originIpLen);
				
				qm.dstIpLen = qm.srcIpLen;
				strncpy(qm.dstIp, qm.srcIp, qm.dstIpLen);
				
				qm.srcPortLen = strlen(serverPortStr);
				strncpy(qm.srcPort,serverPortStr,qm.srcPortLen);

				qm.originPortLen = strlen(serverPortStr);
				strncpy(qm.originPort,serverPortStr,qm.originPortLen);
				
				qm.dstPortLen = msg->srcPortLen;
				strncpy(qm.srcPort, msg->srcPort, qm.dstPortLen);
				
				strncpy(qm.id, msg->id ,qm.idLen);
				qm.cmd = NO_CMD;
				qm.payloadLen = strlen(buf);
				strncpy(qm.payload, buf, qm.payloadLen);
				qm.complete = false;
				uint8_t buf1[2000] = {'\0'};
				print_qm(&qm);
				int len = serialize_query(&qm, buf1,2000 );
				printf("Sending Response %d SockFd == %p\n",len, neighborPtr);
				write(neighborPtr->sockfd, buf1, len);
			}
        		pclose(fp);
			Msg qm;
			qm.msgType = RESPONSE;
			qm.idLen = msg->idLen;
			qm.srcIpLen = strlen(serverIP);
			strncpy(qm.srcIp, serverIP, qm.srcIpLen);
			qm.originIpLen = strlen(serverIP);
			strncpy(qm.originIp, serverIP, qm.originIpLen);
			qm.dstIpLen = msg->srcIpLen;
			strncpy(qm.dstIp, msg->srcIp, qm.dstIpLen);
			qm.dstPortLen = strlen(msg->srcPort);
			strncpy(qm.id, msg->id, qm.idLen);
			qm.cmd = NO_CMD;
			qm.payloadLen = 0;
			strncpy(qm.payload, buf, qm.payloadLen);
			qm.complete = true;
			uint8_t buf1[2000];
			print_qm(&qm);
			int len = serialize_query(&qm, buf1,2000 );
			printf("Sending Complete %d\n",len);
			write(neighborPtr->sockfd, buf1, len);
		}else if(msg->cmd == RM){
		}else if(msg->cmd == DOWNLOAD){
		}
	}else if(msg->msgType == RESPONSE){
		if(strcmp(msg->dstIp,serverIP) && strcmp(msg->dstPort, serverPortStr)){
			printf("Recived Response %s\n",msg->payload);	
		}else{
			uint8_t buf1[2000];
			//
				/*strcpy(msg->srcIpLen, itoa(strlen(serverIP)));
				strncpy(msg.srcIp, serverIP, msg.srcIpLen);

				msg.originIpLen = strlen(serverIP);
				strncpy(qm.originIp, serverIP, qm.originIpLen);
				
				msg.dstIpLen = qm.srcIpLen;
				strncpy(qm.dstIp, qm.srcIp, qm.dstIpLen);
				
				msg.srcPortLen = strlen(serverPortStr);
				strncpy(qm.srcPort,serverPortStr,qm.srcPortLen);

				msg.originPortLen = strlen(serverPortStr);
				strncpy(qm.originPort,serverPortStr,qm.originPortLen);
				
				qm.dstPortLen = msg->srcPortLen;*/
			//
			printf("\nForward the message to the source\n");
			print_qm(msg);
			int len = serialize_query(msg, buf1,2000 );
			printf("Sending %d\n",len);
			write(neighborPtr->sockfd, buf1, len);
		}
	}

	return NULL;
}

void* handle_cmd_msg_types(Msg* q){
	if(q && q->msgType == KEEPALIVE){
		char msgStr[200] = {'\0'};
		snprintf(msgStr, sizeof(msgStr), "\n KeepAlive Received From IP %s Port %s \n", q->srcIp, q->srcPort);
		write_to_log(msgStr);
		pthread_mutex_lock(&ttlMutex);
		received_ttl_msg = true;
		pthread_cond_signal(&ttlCond);
		pthread_mutex_unlock(&ttlMutex);
	} else if(q && q->cmd == LS && q->msgType == REQUEST){
		printf("\nSending Reuqest\n");
		if(add_request(q)){
			if(strcmp(q->dstIp, serverIP) == 0 && strcmp(q->dstPort, serverPortStr) == 0){
				printf("\nRequest for myself\n");
				pthread_t response_forwarder_id;
				pthread_create(&response_forwarder_id, NULL, response_forwarder, q);
				pthread_join(response_forwarder_id, NULL);
			} else {
				printf("\nRequest for Neighbor\n");
				pthread_t request_forwarder_id = 100;
				pthread_create(&request_forwarder_id, NULL, request_forwarder, q);
				pthread_join(request_forwarder_id, NULL);
			}
		}
	} else if(q && q->cmd == RM && q->msgType == REQUEST){

	} else if(q && q->cmd == DOWNLOAD && q->msgType == REQUEST){

	} else if(q && q->msgType == RESPONSE){

	}
	return NULL;
}


void* handle_received_msgs(void* node){
	Peer p = *(Peer*)node;
	pthread_t checkTTL = 100;
	//pthread_create(&checkTTL, NULL, check_ttl, &p.thread);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	while(1){
		fd_set rfds;
		FD_ZERO(&rfds);
		printf("Registering Socket %d\n",p.sockfd);
		FD_SET(p.sockfd, &rfds);
		//struct timeval tv;
		//tv.tv_sec  = 5;
		//tv.tv_usec = 0;
		//Sachin Fix it
		int r = select(p.sockfd + 1, &rfds, NULL, NULL, NULL);
		if (r == 0) {
			char msg[100];
			snprintf(msg, sizeof(msg),"Thread is cancelled %d\n",serverPort);
			write_to_log("Cancelling Receive thread \n");
			pthread_testcancel();
		} else if (r > 0) {
			printf("Handled_received_msg %d\n",r);
			Msg* q = malloc(sizeof(Msg));;
			q->msgType = UNKNOWN;
			read_from_socket(p.sockfd, q);
			printf("Msg Type %d CMD = %d\n ", q->msgType, q->cmd);
			if(q->msgType == UNKNOWN){
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
			} else {
				printf("HANDLE_RECEIVED_MSGS %d %d \n", q->cmd, q->msgType);
				print_qm(q);
				handle_cmd_msg_types(q);
			}
			free(q);
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
				msg.srcIpLen = strlen(serverIP);
				strcpy(msg.srcIp, serverIP);
				char portStr[10];
				itoa(serverPort, portStr);
				msg.srcPortLen = strlen(portStr);
				msg.idLen = 0;
				msg.cmd = NO_CMD;
				strcpy(msg.srcPort,portStr) ;
				msg.complete = true;
				//print_qm(&msg);
				uint8_t buf1[BUF_SIZE];
				int len = serialize_query(&msg, buf1, BUF_SIZE);
				char msgStr[200] = {'\0'};
				snprintf(msgStr, sizeof(msgStr), "\n KeepAlive Sent To %s Port %d \n", temp->ip, temp->port);
				write_to_log(msgStr);
				write(temp->sockfd, buf1, len);
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
			Peer* neighborPtr = head;
			connectionsMade = 0;
			while(neighborPtr){
				if(attempts[neighbor] < numAttempts && (neighborPtr->sockfd == -1) && (strcmp(neighborPtr->ip, serverIP)|| neighborPtr->port > serverPort)){
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
					addr.sin_port = htons(neighborPtr->port);

					if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) <= 0) {
						perror("inet_pton");
					}
					int result = connect(sock_fd, (struct sockaddr *)&addr, sizeof(addr));
				       	if(result < 0) {
						char msgStr[200] = {'\0'};
						snprintf(msgStr, sizeof(msgStr), "\n Connection Rejected by IP %s Port %d\n", neighborPtr->ip, neighborPtr->port);
						write_to_log(msgStr);
					}else{
						printf("Attempts %d Sockfd %d \n",attempts[neighbor], neighborPtr->sockfd );
						char msgStr[200] = {'\0'};
						snprintf(msgStr, sizeof(msgStr), "\n Connection Accepted by IP %s Port %d\n", neighborPtr->ip, neighborPtr->port);
						write_to_log(msgStr);
						pthread_rwlock_wrlock(&(neighborPtr->lock));
						neighborPtr->sockfd = sock_fd;
						pthread_create(&(neighborPtr->thread), NULL, handle_received_msgs, neighborPtr);
						pthread_rwlock_unlock(&(neighborPtr->lock));
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
        					msg.srcIpLen = strlen(serverIP);
        					strcpy(msg.srcIp, serverIP) ;
						char serverPortStr[10];
						itoa(serverPort, serverPortStr);
        					msg.srcPortLen = strlen(serverPortStr);
        					strcpy(msg.srcPort, serverPortStr);
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
				neighborPtr = neighborPtr->next;
				neighbor += 1;
			}
			if(totalNeighbors != connectionsMade){
				sleep(5);
			}else{
				char msgStr[200] = {'\0'};
				snprintf(msgStr, sizeof(msgStr), "\n All Connections are made \n");
				write_to_log(msgStr);
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

void* listRequests(){
	Request* temp =  requestHead;
	while(temp){
		printf("Request ID: %s serverIP %s srcPort %s complete %d \n", temp->id, temp->srcIP, temp->srcPort, temp->complete);
		temp = temp->next;
	}
	return NULL;
}

void* sendInitialRequest(void* reqMsg){
	Msg msg = *(Msg*)reqMsg;
	msg.msgType = REQUEST;
	msg.idLen = 4;
	strcpy(msg.id,"1234");
	msg.originIpLen = strlen(serverIP);
	strcpy(msg.originIp, serverIP);
	msg.originPortLen = strlen(serverPortStr);
	strcpy(msg.originPort, serverPortStr);
	msg.srcIpLen = strlen(serverIP);
	strcpy(msg.srcIp, serverIP);
	msg.srcPortLen = strlen(serverPortStr);
	strcpy(msg.srcPort, serverPortStr);
	msg.complete = true;
	handle_cmd_msg_types(&msg);
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
			case 1:{
				char dstIp[IpAddrLen] = {'\0'};
				char dstPort[PortLen] = {'\0'};
				printf("Enter the server ip");
				scanf("%s", dstIp);
				printf("Enter the Port");
				scanf("%s", dstPort);
				Msg msg;
        			msg.cmd = LS;
				msg.dstIpLen = strlen(dstIp);
				strcpy(msg.dstIp, dstIp);
				msg.dstPortLen = strlen(dstPort);
				strcpy(msg.dstPort, dstPort);
				pthread_t initial_id;
				pthread_create(&initial_id, NULL, sendInitialRequest, &msg);
				break;
			       }
			case 2:{
				printf("Enter the server ip");
				scanf("%s", serverIP);
				printf("Enter the Port");
				scanf("%s", port);
				printf("Enter the File Name");
				scanf("%s", fileName);
				Msg msg;
        			msg.cmd = RM;
				strcpy(msg.payload, fileName);
				msg.payloadLen = strlen(fileName);
				pthread_t initial_id;
				pthread_create(&initial_id, NULL, sendInitialRequest, &msg);
				break;
			       }
			case 3:{
				printf("Enter the File Name");
				scanf("%s", fileName);
				break;
			       }
			case 4:{
				pthread_t t1 = 100;
				pthread_create(&t1, NULL, listNeighbors, NULL);
				pthread_join(t1, NULL);
				break;
			       }
			case 5:{
				pthread_t t2 = 200;
				pthread_create(&t2, NULL, listRequests, NULL);
				pthread_join(t2, NULL);
				break;
			       }

		}

	}
}



int main(int argc, char** argv){
	requestHead = calloc(1, sizeof(Request));
	requestTail = requestHead;
	printf("Argc %d %s \n",argc, argv[1]);
	readFile(argv[1]);
	strcpy(logFileName, serverIP);
	itoa(serverPort, serverPortStr);
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
	//pthread_create(&sendTTL, NULL, send_ttl, NULL);
	pthread_join(connect_with_higher_ip_port, NULL);
	pthread_join(prompt_t, NULL);
	pthread_join(generateId, NULL);
}
