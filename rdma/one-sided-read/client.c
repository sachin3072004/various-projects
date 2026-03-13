#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>
#include  <unistd.h>
#include <assert.h>
#define PORT "9999"
#define SERVER_ADDRESS "172.31.31.182"
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
	struct addrinfo *dst_addr;
        getaddrinfo(SERVER_ADDRESS, PORT, NULL, &dst_addr);
	ret = rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
	struct rdma_cm_event *event;
	rdma_get_cm_event (ch, &event);
	printf("EventX == %d\n", event->event);
	rdma_ack_cm_event(event);
	ret = rdma_resolve_route (id, 2000);
	rdma_get_cm_event (ch, &event);
	printf("EventY == %d\n", event->event);
	rdma_ack_cm_event(event);
	printf("ID VERBS %p \n", id->verbs);
	struct ibv_pd *pd = ibv_alloc_pd(id->verbs);
	if (!pd) {
    		fprintf(stderr, "Failed to allocate PD\n");
    		return -1;
	}
	int cqe = 16;
	struct ibv_cq *cq = ibv_create_cq(id->verbs, cqe, NULL, NULL, 0);	
	void *buffer = calloc(1, BUFFER_SIZE);
	struct ibv_mr *mr = ibv_reg_mr( pd, buffer, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
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
	rdma_create_qp(id, pd, &qp_init_attr );
	struct ibv_qp *qp = id->qp;
	
	struct ibv_recv_wr wr;
	struct ibv_sge sg1;	
	memset(&sg1, 0, sizeof(sg1));
	sg1.addr	= (uintptr_t)buffer;
	sg1.length 	= BUFFER_SIZE;
	sg1.lkey 	= mr->lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = 0;
	wr.sg_list    = &sg1;
	wr.num_sge    = 1;	
	ibv_post_recv(qp, &wr, &bad_wr);		
	struct rdma_conn_param conn_param = {};
	conn_param.initiator_depth = 1;
	conn_param.responder_resources = 1;
	conn_param.rnr_retry_count = 7;	
	printf("\n Before RDMA_CONNECT \n");
	if(rdma_connect(id, &conn_param)){
		perror("rdma_connect");
	}
	printf("Waiting for RDMA_CM_EVENT_ESTABLISHED\n");
	rdma_get_cm_event(ch, &event);
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
	printf("Done RDMA_CM_EVENT_ESTABLISHED\n");
	int n = 0;
	struct ibv_wc wc;
	int num_entries = 1;
	do {
		n = ibv_poll_cq(cq, num_entries, &wc);
		if(n == 0){
			continue;
		}
		if(wc.status != IBV_WC_SUCCESS ){
			printf("Problem with Status");
			return 0;
		}
		if(wc.opcode == IBV_WC_RECV){
			break;
		}
	}while(n == 0);	
	struct MRInfo *mriinfo = (struct MRInfo*)buffer;
	printf("Addr %p key %d sz %d id %d \n", mriinfo->addr,mriinfo->key, mriinfo->sz, mriinfo->id);	

	void *buffer1 = calloc(1, BUFFER_SIZE);
	struct ibv_mr *mr1 = ibv_reg_mr( pd, buffer1, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	struct ibv_sge sge_write = {
			.addr = (uintptr_t)buffer1,
			.length = mriinfo->sz,
			.lkey = mr1->lkey
	};
	struct ibv_send_wr swr = {
		.wr_id = 2,
		.sg_list = &sge_write,
		.num_sge = 1,
		.opcode = IBV_WR_RDMA_READ,
		.send_flags = IBV_SEND_SIGNALED,
		.wr.rdma.remote_addr = mriinfo->addr,
		.wr.rdma.rkey = mriinfo->key
	}, *bad_swr;
	printf("Trying to read from remote\n")	;
	if (ibv_post_send(id->qp, &swr, &bad_swr)) perror("ibv_post_send write");
	/*do {
		n = ibv_poll_cq(cq, 1, &wc);
		if(n == 0){
			continue;
		}
		if(wc.status != IBV_WC_SUCCESS ){
			printf("Problem with Status");
			return 0;
		}
		if(wc.opcode == IBV_WC_RDMA_READ){
			break;
		}
	}while(n == 0);*/
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (wc.status != IBV_WC_SUCCESS) {
	fprintf(stderr, "RDMA Read failed: %s\n",
	ibv_wc_status_str(wc.status));
	return 1;
	}
	assert(wc.opcode == IBV_WC_RDMA_READ); // not IBV_WC_SEND!

	printf("out\n");
	printf("Buf %s\n", buffer1);
	while(1){
		sleep(5);
	}	
	
}
