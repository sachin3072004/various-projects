#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#define PORT "9999"
#define BUFFER_SIZE 4096

struct MRInfo{
	uint64_t addr;
	uint32_t sz;
	uint32_t key;
	uint32_t id;
};

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id;
	int ret = rdma_create_id(ch, &id, NULL, RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
	char* specific_ip_address = "172.31.31.182";
        addr.sin_addr.s_addr = inet_addr(specific_ip_address);;
	printf("Id == %p\n",id);	
	rdma_bind_addr (id, (struct sockaddr*)&addr);
	int backlog = 10;
	ret = rdma_listen(id, backlog);
	struct rdma_cm_event *event;
	printf("\n RADMA Listening Event \n");
	if(rdma_get_cm_event(ch, &event)){
                perror("rdma_get_cm_event");
                return 1;
        }
	struct rdma_cm_id* client_id = event->id;
        rdma_ack_cm_event(event);

	struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
	int cqe = 16;
	struct ibv_cq *cq = ibv_create_cq(client_id->verbs, cqe, NULL, NULL, 0);	
	void *buffer = calloc(1, BUFFER_SIZE);
	strcpy(buffer, "Sachin Gupta is working!!");
	struct ibv_mr *mr = ibv_reg_mr( pd, buffer, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

	void *recv_buffer = calloc(1, BUFFER_SIZE);
	struct ibv_mr *recv_mr = ibv_reg_mr( pd, recv_buffer, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);

	struct ibv_recv_wr *bad_wr;
	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = cq; // Previously created
	qp_init_attr.recv_cq = cq; // Previously created
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.cap.max_send_wr = 10;
	qp_init_attr.cap.max_recv_wr = 10;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	rdma_create_qp(client_id, pd, &qp_init_attr );
	struct ibv_qp *qp = client_id->qp;
	if(!qp){
		perror("rdma_create_qp");
	}	
	struct ibv_recv_wr wr;
	struct ibv_sge sg1;	
	memset(&sg1, 0, sizeof(sg1));
	sg1.addr	= (uintptr_t)recv_buffer;
	sg1.length 	= BUFFER_SIZE;
	sg1.lkey 	= recv_mr->lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = 0;
	wr.sg_list    = &sg1;
	wr.num_sge    = 1;	
	ibv_post_recv(qp, &wr, &bad_wr);		
	struct rdma_conn_param conn_param = {};
	memset(&conn_param, 0,sizeof(conn_param));
	conn_param.initiator_depth = 1;
     	conn_param.responder_resources = 1;
     	conn_param.rnr_retry_count = 7;
	rdma_accept (client_id, &conn_param);
	if (rdma_get_cm_event(ch, &event)) perror("rdma_get_cm_event");
	if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
		fprintf(stderr, "Expected ESTABLISHED, got %d\n", event->event);
		return 1;
	}
	rdma_ack_cm_event(event);
	printf("Buffer == %s\n", buffer);
	struct MRInfo mri;
	struct ibv_mr *send_mr = ibv_reg_mr( pd, &mri, sizeof(struct MRInfo), IBV_ACCESS_LOCAL_WRITE);
	mri.addr = (uintptr_t)buffer;
	mri.key = mr->rkey;
	mri.sz = BUFFER_SIZE; 
	mri.id = 12345;
	printf("Sending MRI %p Key %d SZ %d id %d \n", mri.addr, mri.key, mri.sz, mri.id);
	struct ibv_sge send_sge = {0};
	//memset(&sg, 0, sizeof(sg));
	send_sge.addr	  = (uintptr_t)&mri;
	send_sge.length = sizeof(struct MRInfo);
	send_sge.lkey	  = send_mr->lkey;

	struct ibv_send_wr wr1 = {0}; 
	//memset(&wr1, 0, sizeof(wr1));
	wr1.wr_id      = 0;
	wr1.sg_list    = &send_sge;
	wr1.num_sge    = 1;
	wr1.opcode     = IBV_WR_SEND;
	wr1.send_flags = IBV_SEND_SIGNALED;	

	struct ibv_send_wr *bad_wr1;
	printf("Ready to send\n");
	if(ibv_post_send(client_id->qp, &wr1, &bad_wr1)){
		perror("ibv_post_send");
	}
	int ne;
	struct ibv_wc wc1;
    	while ((ne = ibv_poll_cq(cq, 1, &wc1)) == 0)
   	if (ne < 0) perror("ibv_poll_cq");
    	if (wc1.status != IBV_WC_SUCCESS)
    		perror("SEND completion");
	printf("Already Sent %s\n", buffer);
	while(1){
		sleep(5);
	}		
	
}
