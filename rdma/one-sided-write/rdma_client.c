#include <stdio.h>
#include <infiniband/verbs.h>
#include <rdma/rdam_cma.h>
#define BUF_LEN 4096

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id, *client_id;
	rdma_create_id (ch, &id, NULL, RDMA_PS_TCP);
	int backlog = 10;
	rdma_listen (id, backlog);
	struct rdma_cm_event *event;
	rdma_get_cm_event(ch, &event);
	rdma_ack_cm_event(event);
	client_id = event->id;
	struct ibv_pd *pd = ibv_alloc_pd(client_id->verb);	
	char* buf = calloc(1,BUF_LEN);	
	struct ibv_mr *mr = ibv_reg_mr(pd, buf, BUF_LEN, IBV_ACCESS_LOCAL_WRITE);
	int cqe = 16;
	struct ibv_cq *cq = ibv_create_cq(client_id->verb, cqe, NULL, NULL, 0);	
	struct ibv_qp_init_attr init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = cq;
	qp_init_attr.recv_cq = cq;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.cap.max_send_wr  = 2;
	qp_init_attr.cap.max_recv_wr  = 2;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	struct ibv_qp *qp = ibv_create_qp(pd, &init_attr);
	struct ibv_recv_wr *bad_wr;
	struct ibv_recv_wr *wr;
	struct ibv_sge sg1;	
	memset(&sg1, 0, sizeof(sg1));
	sg.addr	  = (uintptr_t)buf;
	sg.length = BUF_LEN;
	sg.lkey	  = mr->lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = 0;
	wr.sg_list    = &sg;
	wr.num_sge    = 1;
	ibv_post_recv(qp, wr, &bad_wr);	
	struct ibv_sge sg2;	
	memset(&sg2, 0, sizeof(sg2));
        sg.addr   = (uintptr_t)buf;
        sg.length = BUF_LEN;
        sg.lkey   = mr->rkey;
        memset(&wr, 0, sizeof(wr));
        wr.wr_id      = 0;
        wr.sg_list    = &sg;
        wr.num_sge    = 1;	
	ibv_post_send(qp, wr, &bad_wr);		
	struct ibv_wc wc;
	int n;
	do {
    		n = ibv_poll_cq(send_cq, 1, &wc);
	} while (wc.status != IBV_WC_SUCCESS);	
	sleep(5);	
	printf("Buffer on Server side %s \n", buf);	
	
}
