#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pthread.h>
int serverPort = 0 ;
char serverPortStr[10] = {'\0'};
char serverIP[100] = {'\0'};
typedef struct Peer{
	char ip[100];
	int port;
	int sockfd;
	pthread_rwlock_t lock;
	struct Peer* next;
	struct Peer* prev;
	pthread_t  thread;
} Peer;

Peer* head  = NULL;
Peer* tail = NULL;
int totalNeighbors = 0;

void itoa(int num, char* str){
	int count = 0;
	while(num){
		str[count] = num % 10 + '0';
		count += 1;
		num = num / 10;
	}
	int i = 0;
	int j = count-1;
	while(i < j){
		char temp = str[i];
		str[i] = str[j];
		str[j] = temp;
		i += 1;
		j -= 1;
	}
	str[count] = '\0';
}

void readFile(char* fileName){
	FILE *fp = fopen(fileName, "r");
	char line[1000];
	char colon = ':';
	char comma = ',';
	bool first = false;
	while(fgets(line, sizeof(line), fp)){
		char* firstColonPtr = strchr(line, colon);
		char* commaPtr = strchr(line, comma);
		char* secondColonPtr = strchr(commaPtr, colon);
		int ipLen = commaPtr - firstColonPtr - 1;
		int portLen = strlen(line) - 1 - (secondColonPtr - line);
		char ipStr[100] = {'\0'};
		char portStr[100] = {'\0'};
		strncpy(ipStr, firstColonPtr + 1, ipLen);
		strncpy(portStr, secondColonPtr + 1, portLen);
		int port = atoi(portStr);
		if(!first){
			strncpy(serverIP, ipStr, strlen(ipStr) + 1);
			serverPort = port;
			first = true;
			
		}else{
			totalNeighbors += 1;
			Peer* peer = malloc(sizeof(Peer));
			peer->port = port;
			strcpy(peer->ip,ipStr + 3);
			peer->sockfd = -1;
			peer->thread = totalNeighbors ;
			pthread_rwlock_init(&peer->lock, NULL);
			if(!head){
				head = peer;
				tail = peer;
			}else{
				tail->next = peer;
				peer->prev = tail;
				tail = tail->next;
				tail->next = NULL;
			}
		}
	}
	fclose(fp);

}
