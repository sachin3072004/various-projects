#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdlib.h>
#include  <unistd.h>
#define SERVER_ADDRESS "172.31.31.182"
#define PORT "9999"
#define BUFFER_SIZE 150
#define CQ_DEPTH 32
enum Action{
	FILENAME,
	DATA,
	RECVD
};

struct Msg{
	enum Action action;
	char   data[1000];	
};

struct Bookkeeper{
        struct rdma_cm_id *id;
        struct ibv_pd *pd;
        struct ibv_cq *cq;
        struct ibv_qp *qp;
	struct ibv_comp_channel *comp_channel;
        char* send_buf;
        struct ibv_mr *send_mr;
	struct ibv_srq *srq;
        char* recv_buf;
        struct ibv_mr *recv_mr;
	int send_num;
        int recv_num;
        int last_sent;
        int last_recv;
};

struct Bookkeeper bk;

enum SendRecv {
        Send,
        Recv
};

void poll_cq(int index, enum SendRecv sendRecv){
        printf("Expected %d Last_Recv %d SendRecv %d \n",index, bk.last_recv, sendRecv);
	 if(sendRecv == Recv && bk.last_recv >= index){
                return;
        }
        if(sendRecv == Send && bk.last_sent >= index){
                return;
        }
        struct ibv_cq *cq;
        void *cq_ctx;
        printf("In POLL CQ waiting for get CQ event \n");
        ibv_get_cq_event(bk.comp_channel, &cq, &cq_ctx);

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
                        printf("Sent %s WR_ID %d \n",bk.send_buf, wc[i].wr_id);
                        bk.last_sent = wc[i].wr_id;
                }else if(wc[i].opcode == IBV_WC_RECV){
                        printf("Received %s WR_ID %d \n",bk.recv_buf, wc[i].wr_id);
                        bk.last_recv = wc[i].wr_id;
                }

        }
}

void create_srq(){
        struct ibv_srq_init_attr srq_attr = {
                .attr = {
                        .max_wr = 10,
                        .max_sge = 1,
                },
        };
        bk.srq = ibv_create_srq(bk.pd, &srq_attr);
}

void setup_receive_buf(){
        struct ibv_sge sge = {
                .addr = (uintptr_t)bk.recv_buf,
                .length = BUFFER_SIZE,
                .lkey = bk.recv_mr->lkey,
                };
        struct ibv_recv_wr *bad_wr;
        struct ibv_recv_wr wr = {
                .wr_id = ++bk.recv_num,
                .sg_list = &sge,
                .num_sge = 1,
                };
        //ibv_post_recv(bk.qp, &wr, &bad_wr);
	ibv_post_srq_recv(bk.srq, &wr, &bad_wr);

}

void  get_data_from_server(){
        poll_cq(bk.recv_num, Recv);
	printf("Started Polling for RECV Action \n");
	printf("Done Polling for RECV Action \n");
        printf("Server Sent: %s\n", bk.recv_buf);
        setup_receive_buf();

}

void setup_send_buf(){
         struct ibv_sge send_sge = {
        .addr = (uintptr_t)bk.send_buf,
        .length = BUFFER_SIZE,
        .lkey = bk.send_mr->lkey,
        };
        struct ibv_send_wr send_wr = {
        .wr_id = ++bk.send_num,
        .sg_list = &send_sge,
        .num_sge = 1,
        .opcode = IBV_WR_SEND,
        .send_flags = IBV_SEND_SIGNALED,
        };
        struct ibv_send_wr *bad_send;
	printf("Sent == %s\n ", bk.send_buf);
        ibv_post_send(bk.qp, &send_wr, &bad_send);
}

void send_line(char* line){
	strcpy(bk.send_buf, line);
        setup_send_buf();
	printf("Polling Started for Send Action\n");
        poll_cq(bk.send_num, Send);
	printf("Polling Ended for Send Action\n");
        printf("Client Sent: %s\n", bk.send_buf);
}

void setup_connection(){
        printf("Id %p \n", bk.id);
        bk.pd = ibv_alloc_pd(bk.id->verbs);
	create_srq();
        bk.recv_buf = calloc(1, BUFFER_SIZE);
        bk.recv_mr = ibv_reg_mr(bk.pd, bk.recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	bk.comp_channel = ibv_create_comp_channel(bk.id->verbs);
        //bk.cq = ibv_create_cq(bk.id->verbs, 16, NULL, bk.comp_channel, 0);
	bk.cq = ibv_create_cq(bk.id->verbs, CQ_DEPTH, NULL, bk.comp_channel, 0);
	ibv_req_notify_cq(bk.cq, 0);
	printf("BK.CQ %p \n", bk.cq);
        bk.send_buf = calloc(1, BUFFER_SIZE);
        bk.send_mr = ibv_reg_mr(bk.pd, bk.send_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        printf("Setup_connection \n");
        struct ibv_qp_init_attr qp_init_attr;
        memset(&qp_init_attr, 0, sizeof(qp_init_attr));
        qp_init_attr.send_cq = bk.cq; // Previously created
        qp_init_attr.recv_cq = bk.cq; // Previously created
	qp_init_attr.srq    = bk.srq;
        qp_init_attr.qp_type = IBV_QPT_RC;
        qp_init_attr.cap.max_send_wr = 10;
        qp_init_attr.cap.max_recv_wr = 0;
        qp_init_attr.cap.max_send_sge = 1;
        qp_init_attr.cap.max_recv_sge = 1;
        if(rdma_create_qp (bk.id, bk.pd, &qp_init_attr)){
		perror("rdma_create_qp");
	}
	bk.qp = bk.id->qp;
}

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
        rdma_create_id(ch, &bk.id, NULL, RDMA_PS_TCP);
	struct addrinfo *dst_addr;
	getaddrinfo(SERVER_ADDRESS, PORT, NULL, &dst_addr);
	rdma_resolve_addr (bk.id, NULL, dst_addr->ai_addr, 2000);
	struct rdma_cm_event *event;
	rdma_get_cm_event (ch, &event);
	rdma_ack_cm_event(event);
	if(rdma_resolve_route (bk.id, 2000)){
		perror("rdma_resolve_route");
	}
	rdma_get_cm_event (ch, &event);
	rdma_ack_cm_event(event);
	setup_connection();	
	setup_receive_buf();
        struct rdma_conn_param conn_param = {
		.initiator_depth = 1, .responder_resources = 1
	};	
	if(rdma_connect (bk.id, &conn_param)){
		perror("rdma_connect");
	}
	rdma_get_cm_event(ch, &event);
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
	char line[1000] = {'\0'};
	strcpy(line, "/home/ec2-user/various-projects/rdma/multi-client-server/hello2.txt");
	send_line(line);
	while(1){
		get_data_from_server();
		char rec[100] = "Ack: ";
		strcat(rec, bk.recv_buf);
		printf("Send Ack\n");
		send_line(rec);
	}
	while(1){
		sleep(10);
	}	
}
