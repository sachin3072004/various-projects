#include <stdio.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#define PORT "9999"
#define BUF_LEN 4096

struct rdma_buffer{
	uint64_t addr; // remote virtual address of the data buffer
	uint32_t rkey; // remote rkey
	uint32_t len; 
	int id;
};

int main(){
	struct rdma_buffer rb;
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id, *client_id;
	rdma_create_id (ch, &id, NULL, RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
        addr.sin_addr.s_addr = INADDR_ANY;
	
	rdma_bind_addr (id, (struct sockaddr*)&addr);
	int backlog = 10;
	rdma_listen (id, backlog);
	struct rdma_cm_event *event;
	if(rdma_get_cm_event(ch, &event)){
		perror("rdma_get_cm_event");
		return 1;
	}
	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
    		fprintf(stderr, "Expected CONNECT_REQUEST, got %d (status %d)\n",
            	event->event, event->status);
    		rdma_ack_cm_event(event);
    		return 1;
	}
	client_id = event->id;
	rdma_ack_cm_event(event);
	printf("\n After client ID %p \n", client_id->verbs);
	if(!client_id->verbs){
		printf("Client_id verb is null\n");
		return 0;
	}
	struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);	

	//struct ibv_pd *ctl_pd = ibv_alloc_pd(client_id->verbs);	
	printf("\n After Ctl Protection Domain \n");
	char* buf = calloc(1,BUF_LEN);	
	
	printf("PD Created \n");
	struct ibv_mr *mr = ibv_reg_mr(pd, buf, BUF_LEN, IBV_ACCESS_LOCAL_WRITE  |IBV_ACCESS_REMOTE_WRITE);
	//struct ibv_mr *ctl_mr = ibv_reg_mr(ctl_pd, &rb, BUF_LEN, IBV_ACCESS_LOCAL_WRITE |IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	struct ibv_mr *ctl_mr = ibv_reg_mr(pd, &rb, BUF_LEN, IBV_ACCESS_LOCAL_WRITE |IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	printf("CTRL_R %p\n",ctl_mr);
	int cqe = 16;
	printf("CQ Created \n");
	struct ibv_cq *cq = ibv_create_cq(client_id->verbs, cqe, NULL, NULL, 0);	
	struct ibv_qp_init_attr init_attr;
	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	init_attr.qp_type = IBV_QPT_RC;
	init_attr.cap.max_send_wr  = 16;
	init_attr.cap.max_recv_wr  = 16;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	printf("Before QP Created \n");
	//int ret = rdma_create_qp(client_id, ctl_pd, &init_attr);
	int ret = rdma_create_qp(client_id, pd, &init_attr);
	if(ret){
		perror("rdma_create_qp");
		 fprintf(stderr, "ret=%d errno=%d\n", ret, errno);
		return 0;
	}
	struct ibv_qp *qp = client_id->qp;
	printf("QP %p \n", qp);
	if(!qp){
		perror("rdma_create_qp");
		return 1;
	}
	printf("\nServer QP created\n");
	struct ibv_recv_wr *bad_wr;
	struct ibv_recv_wr wr;
	struct ibv_sge sg1;	
	memset(&sg1, 0, sizeof(sg1));
	sg1.addr = (uintptr_t)&rb;
	sg1.length = BUF_LEN;
	sg1.lkey   = ctl_mr->lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = 0;
	wr.sg_list    = &sg1;
	wr.num_sge    = 1;
	printf("\n IBV_POST_RECV \n");
	if(ibv_post_recv(qp, &wr, &bad_wr)){
		perror("ibv_post_recv");
	}
	printf("\n AFTER IBV_POST_RECV \n");
	// 7) Accept connection
	struct rdma_conn_param conn_param = {};
	if (rdma_accept(client_id, &conn_param)) perror("rdma_accept");
	printf(" \n Accepted\n");
	printf("Start Waiting for RDMA_CM_EVENT_ESTABLISHED \n");
	if (rdma_get_cm_event(ch, &event)) perror("rdma_get_cm_event");
	printf("Waiting for RDMA_CM_EVENT_ESTABLISHED \n");
	if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
		fprintf(stderr, "Expected ESTABLISHED, got %d\n", event->event);
		return 1;
	}
	rdma_ack_cm_event(event);

	printf("\nServer POST RECV done\n");
	struct ibv_sge sg2;	
	struct ibv_send_wr wr2;
	struct ibv_send_wr *bad_wr2;
	rb.addr = (uint64_t)(uintptr_t)buf;
	rb.len = BUF_LEN;
	rb.rkey =  mr->rkey;
	rb.id = 123456;
	printf("addr %p lenght %d lkey %d ID %d \n",rb.addr, rb.len, rb.rkey, rb.id);
	memset(&sg2, 0, sizeof(sg2));
        sg2.addr   = (uintptr_t)&rb;
        sg2.length = sizeof(struct rdma_buffer);
        sg2.lkey   = ctl_mr->lkey;
        memset(&wr2, 0, sizeof(wr2));
        wr2.wr_id      = 123;
        wr2.sg_list    = &sg2;
        wr2.num_sge    = 1;
	wr2.opcode = IBV_WR_SEND;
	wr2.send_flags = IBV_SEND_SIGNALED;  // needed so the CQ gets a completion
	if(ibv_post_send(qp, &wr2, &bad_wr2)){
		perror("ibv_post_send");
	}
	printf("\n Before Sleep\n");
	sleep(5);
	printf("Buf %s \n",buf);
	while(1){
		sleep(1);
	}
	
}
