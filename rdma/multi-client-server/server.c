#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 150
#define PORT "9999"
#define CQ_DEPTH 64
enum Action{
        FILENAME,
        DATA, 
	RECVD
};

struct Msg{
        enum Action action;
        char   data[1000];
};

struct ibv_pd *pd;
struct ibv_comp_channel *comp_channel;
struct ibv_srq *srq;

struct Bookkeeper{
	struct rdma_cm_id *id;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	char* send_buf;
	struct ibv_mr *send_mr;
	char* recv_buf;
	struct ibv_mr *recv_mr;
	int send_num;
	int recv_num;
	int last_sent;
	int last_recv;
};

struct Bookkeeper bk[100];

enum SendRecv {
	Send = 0,
	Recv	
};

void poll_cq(int threadNo,int index,enum SendRecv sendRecv){
	if(sendRecv == Recv && bk[threadNo].last_recv >= index){
		return;
	}	
	if(sendRecv == Send && bk[threadNo].last_sent >= index){
		return;
	}	
	struct ibv_cq *cq;
	void *cq_ctx;
	printf("In POLL CQ waiting for get CQ event %d \n", sendRecv);	
	ibv_get_cq_event(comp_channel, &cq, &cq_ctx);

	printf("After waiting CQ got an event \n");	
	ibv_ack_cq_events(cq, 1);
	ibv_req_notify_cq(cq, 0);
	struct ibv_wc wc[200];
	int n = 0;
	do {
		//n = ibv_poll_cq(bk.cq, 1, &wc);
		n = ibv_poll_cq(cq, 200, wc);
	}while(n == 0);
	printf("N == %d \n", n);
	for(int i =0;i<n;i++){
		if(wc[i].status != IBV_WC_SUCCESS){
			printf("Error %s\n", ibv_wc_status_str(wc[i].status));
			exit(1);
		}
		printf("I %d OPCODE: %d Send %d Recv %d \n",i,wc[i].opcode,IBV_WC_SEND, IBV_WC_RECV);
		if(wc[i].opcode == IBV_WC_SEND){
			printf("Sent %s WR_ID %d \n",bk[threadNo].send_buf, wc[i].wr_id);
			bk[threadNo].last_sent = wc[i].wr_id;
		}else if(wc[i].opcode == IBV_WC_RECV){
			printf("Received %s WR_ID %d \n",bk[threadNo].recv_buf, wc[i].wr_id);
			bk[threadNo].last_recv = wc[i].wr_id;
		}
		
	}
}

void setup_receive_buf(int threadNo){
	struct ibv_sge sge = {
                .addr = (uintptr_t)bk[threadNo].recv_buf,
                .length = BUFFER_SIZE,
                .lkey = bk[threadNo].recv_mr->lkey,
                };
        struct ibv_recv_wr *bad_wr;
        struct ibv_recv_wr wr = {
                .wr_id = ++bk[threadNo].recv_num,
                .sg_list = &sge,
                .num_sge = 1,
                };
	printf("QP %p \n",bk[threadNo].qp);
	//ibv_post_recv(bk.qp, &wr, &bad_wr);
	ibv_post_srq_recv(srq, &wr, &bad_wr);
		
}

void create_srq(){
	struct ibv_srq_init_attr srq_attr = {
		.attr = {
			.max_wr = 10,
			.max_sge = 1,
		},
	};
	if(!srq){
		srq = ibv_create_srq(pd, &srq_attr);
	}
}

void  get_data_from_client(int threadNo){
	printf("Recv Polling Started\n");
	poll_cq(threadNo, bk[threadNo].recv_num, Recv);	
	printf("Recv Polling Ended\n");
	printf("Server Received: %s\n", bk[threadNo].recv_buf);
	setup_receive_buf(threadNo);
	
}

void setup_send_buf(int threadNo){
	 struct ibv_sge send_sge = {
        .addr = (uintptr_t)bk[threadNo].send_buf,
        .length = BUFFER_SIZE,
        .lkey = bk[threadNo].send_mr->lkey,
        };
        struct ibv_send_wr send_wr = {
        .wr_id = ++bk[threadNo].send_num,
        .sg_list = &send_sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED,
        };
        struct ibv_send_wr *bad_send;
        ibv_post_send(bk[threadNo].qp, &send_wr, &bad_send);	
}

void send_line(int threadNo, char* line){
	memset(bk[threadNo].send_buf,'\0', BUFFER_SIZE);
	strcpy(bk[threadNo].send_buf, line);
	setup_send_buf(threadNo);
	printf("Send Polling Started\n");
	poll_cq(threadNo, bk[threadNo].send_num, Send);	
	printf("Send Polling Ended\n");
	printf("Server Sent: %s\n", bk[threadNo].send_buf);
}

void setup_connection(int threadNo){
	printf("Id %d %p \n",threadNo,  bk[threadNo].id);
	if(!pd){
		pd = ibv_alloc_pd(bk[threadNo].id->verbs);
	}
	create_srq();
	bk[threadNo].recv_buf = calloc(1, BUFFER_SIZE);
	bk[threadNo].recv_mr = ibv_reg_mr(pd, bk[threadNo].recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	if(!comp_channel){
		comp_channel = ibv_create_comp_channel(bk[threadNo].id->verbs);
	}
	bk[threadNo].cq = ibv_create_cq(bk[threadNo].id->verbs, CQ_DEPTH, NULL, comp_channel, 0);
	ibv_req_notify_cq(bk[threadNo].cq, 0);
	bk[threadNo].send_buf = calloc(1, BUFFER_SIZE);
	bk[threadNo].send_mr = ibv_reg_mr(pd, bk[threadNo].send_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	printf("Setup_connection \n");
	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = bk[threadNo].cq; // Previously created
	qp_init_attr.recv_cq = bk[threadNo].cq; // Previously created
	qp_init_attr.srq    = srq;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.cap.max_send_wr = 10;
	qp_init_attr.cap.max_recv_wr = 0;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	rdma_create_qp (bk[threadNo].id, pd, &qp_init_attr);
	bk[threadNo].qp = bk[threadNo].id->qp;
	printf("Created QP %d\n ", bk[threadNo].qp->qp_num);
}


void* handle_client_request(void* args){
	int index = *(int*)args;
	printf("Index == %d\n", index);
	setup_connection(index);
	setup_receive_buf(index);
	struct rdma_conn_param conn_param = {};
	rdma_accept (bk[index].id, &conn_param);
	get_data_from_client(index);	
	char fileName[100];
	strcpy(fileName, bk[index].recv_buf); 
	printf("FileName %s\n", fileName);
	FILE* fp = fopen(fileName, "r");
	if(!fp){
		printf("File failed to open");
		exit(0);
	}

	char line[100] = {'\0'};
	while(fgets(line, 100, fp) != NULL){
		printf("Ready to Send %s\n",line);
		send_line(index, line);
		get_data_from_client(index);
	}
	fclose(fp);	
	while(1){
		sleep(10);
	}		
}

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id,*client_id;
	rdma_create_id(ch, &id, NULL, RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
	char* specific_ip_address = "172.31.31.182";
        addr.sin_addr.s_addr = inet_addr(specific_ip_address);;
	rdma_bind_addr (id, (struct sockaddr*)&addr);
	int backlog = 10;
	rdma_listen(id, backlog);
	int num = 0;
	int thread_ids[100] = {0};
	for(int i = 0;i<100;i++){
		thread_ids[i] = i;
	}
	pthread_t thread[100];
	while(1){
		struct rdma_cm_event *event;
		printf("Num ====================================================== %d\n", num);
		rdma_get_cm_event (ch, &event);
		bk[num].id = event->id;
		rdma_ack_cm_event (event);	
		printf("\n Thread Creation \n");
		if(event->event == RDMA_CM_EVENT_CONNECT_REQUEST){
			pthread_create(&thread[num], NULL, &handle_client_request, &thread_ids[num]);
			num += 1;
		}
	}
	
	
}
