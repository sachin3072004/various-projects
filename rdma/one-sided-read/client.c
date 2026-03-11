#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdlib.h>

#define PORT "9999"
#define SERVER_ADDRESS "172.31.31.182"
#define BUFFER_SIZE 4096

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id;
	int ret = rdma_create_id(ch, &id, NULL, RDMA_PS_TCP);
	struct addrinfo *dst_addr;
        getaddrinfo(SERVER_ADDRESS, PORT, NULL, &dst_addr);
	ret = rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
	struct rdma_cm_event *event;
	rdma_get_cm_event (ch, &event);
	rdma_ack_cm_event(event);
	ret = rdma_resolve_route (id, 20000);
	rdma_get_cm_event (ch, &event);
	rdma_ack_cm_event(event);
	struct rdma_conn_param conn_param;
	struct ibv_pd *pd = ibv_alloc_pd(id->verbs);
	if (!pd) {
    		fprintf(stderr, "Failed to allocate PD\n");
    		return -1;
	}
	int cqe = 16;
	struct ibv_cq *cq = ibv_create_cq(id->verbs, cqe, NULL, NULL, 0);	
	void *buffer = calloc(0, BUFFER_SIZE);
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
	rdma_connect(id, &conn_param);
	
	
}
