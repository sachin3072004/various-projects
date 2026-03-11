#include <stdio.h>
#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>
#include <unistd.h>
#include <stdlib.h>
#define BUF_LEN 4096

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PORT "9999"
#define SERVER_ADDR "172.31.31.182"

struct rdma_buffer{
        uint64_t addr; // remote virtual address of the data buffer
        uint32_t rkey; // remote rkey
        uint32_t len;
	int id;
};

static int poll_cq_for(struct ibv_cq *cq, uint64_t expected_wr_id,
                       enum ibv_wc_opcode expected_op)
{
    struct ibv_wc wc;
    int n;
    for (;;) {
        n = ibv_poll_cq(cq, 1, &wc);
        if (n < 0)  { perror("ibv_poll_cq"); return -1; }
        if (n == 0) continue;
        if (wc.status != IBV_WC_SUCCESS) {
            fprintf(stderr, "WC error: %s (wr_id=%lu)\n",
                    ibv_wc_status_str(wc.status), (unsigned long)wc.wr_id);
            return -1;
        }
        if (wc.wr_id == expected_wr_id && wc.opcode == expected_op)
            return 0;
        /* Unexpected completion — log and keep waiting */
        printf("Unexpected WC: wr_id=%lu opcode=%d — continuing\n",
               (unsigned long)wc.wr_id, wc.opcode);
    }
}

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id;
	rdma_create_id (ch, &id, NULL, RDMA_PS_TCP);

	struct addrinfo *dst_addr;
        getaddrinfo(SERVER_ADDR, PORT, NULL, &dst_addr);	
	
	struct rdma_cm_event *event;
	rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
	rdma_get_cm_event(ch, &event);
	rdma_ack_cm_event(event);
	
	rdma_resolve_route (id, 2000);
	rdma_get_cm_event(ch, &event);
	rdma_ack_cm_event(event);
	printf("\n PD CREATION \n");
	struct ibv_pd *pd = ibv_alloc_pd(id->verbs);	
	char* buf = calloc(1,BUF_LEN);	
	printf("\n Memory Region \n");
	struct ibv_mr *mr = ibv_reg_mr(pd, buf, BUF_LEN, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	int cqe = 16;
	printf("\n CQ CREATED \n");
	struct ibv_cq *cq = ibv_create_cq(id->verbs, cqe, NULL, NULL, 0);	
	struct ibv_qp_init_attr qp_init_attr;
	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq = cq;
	qp_init_attr.recv_cq = cq;
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.cap.max_send_wr  = 2;
	qp_init_attr.cap.max_recv_wr  = 2;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	printf(" \n Before Queue Pair created \n");
	rdma_create_qp(id, pd, &qp_init_attr);
	struct ibv_qp *qp = id->qp;
	//struct ibv_qp *qp = ibv_create_qp(pd, &qp_init_attr);
	printf(" \n Queue Pair created \n");
	struct ibv_recv_wr *bad_wr;
	struct ibv_recv_wr wr;
	struct ibv_sge sg1;	
	memset(&sg1, 0, sizeof(sg1));
	sg1.addr	  = (uintptr_t)buf;
	sg1.length = BUF_LEN;
	sg1.lkey	  = mr->lkey;
	printf("\n XXX POST_RECV XX \n");
	memset(&wr, 0, sizeof(wr));
	wr.wr_id      = 0;
	wr.sg_list    = &sg1;
	wr.num_sge    = 1;
	printf("\n YYY POST_RECV YYY \n");
	printf("\n POST_RECV \n");
	ibv_post_recv(qp, &wr, &bad_wr);	
	
	struct rdma_conn_param conn_param = {};
	conn_param.initiator_depth = 1;
	conn_param.responder_resources = 1;
	conn_param.rnr_retry_count = 7;	
	printf("\n rdma_connect\n");
	rdma_connect (id, &conn_param);
	rdma_get_cm_event(ch, &event);
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
        printf("Connected to server\n");
	printf("\nAfter rdma_connect\n");
	struct ibv_wc wc;
	int n = 0;
	do {
		n = ibv_poll_cq(cq, 1, &wc);
		if(n == 0){
                        continue;
                }
                if(wc.status != IBV_WC_SUCCESS){
                        printf("IBV_WC_SUUCESSNOT");
                        break;
                }
                if(wc.opcode == IBV_WC_SEND){
                        printf("SEND HAPPENED");
                        n = 0;
                        continue;
                }
                if(wc.opcode == IBV_WC_RECV){
                        printf("RECEVIED %d \n", wc.wr_id);
                        break;
                }
	}while(n == 0);
	printf("WR_ID %d\n", wc.wr_id);
	struct rdma_buffer *rbuf = (struct rdma_buffer*)buf;	
	printf("RDMA CLIENT Addr %p Key %d  len %d ID %d \n", rbuf->addr, rbuf->rkey, rbuf->len, rbuf->id);
	
	/////////
	char *write_buf = calloc(1, BUF_LEN);
    if (!write_buf) { perror("calloc write_buf"); return 1; }

    struct ibv_mr *write_mr = ibv_reg_mr(pd, write_buf, BUF_LEN,
                                         IBV_ACCESS_LOCAL_WRITE);
    if (!write_mr) { perror("ibv_reg_mr (write)"); return 1; }

    printf("MRs registered\n");
	////////////
	snprintf(write_buf, BUF_LEN, "Hello World %d\n",10);
	struct ibv_sge sge_write = {
.addr = (uintptr_t)write_buf,
.length = strlen(write_buf) + 1,
.lkey = write_mr->lkey
};
struct ibv_send_wr swr = {
.wr_id = 2,
.sg_list = &sge_write,
.num_sge = 1,
.opcode = IBV_WR_RDMA_WRITE,
.send_flags = IBV_SEND_SIGNALED,
.wr.rdma.remote_addr = rbuf->addr,
.wr.rdma.rkey = rbuf->rkey
}, *bad_swr;
printf("Buf %s\n", write_buf);
if (ibv_post_send(id->qp, &swr, &bad_swr)) perror("ibv_post_send write");		
while (1) {
	printf("Before Status %d\n", wc.status);
	int n = ibv_poll_cq(cq, 1, &wc);
	if (n < 0) perror("ibv_poll_cq");
	if (n == 0) continue;
	if (wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "WC error %d\n", wc.status);
		return 1;
	}
	if (wc.wr_id == 2 && wc.opcode == IBV_WC_RDMA_WRITE){
		printf("Client has sent \n ");
		break;
	}
}
	printf("\n Sent\n");
	/*if (poll_cq_for(cq, 2 , IBV_WC_RDMA_WRITE) != 0) {
        	fprintf(stderr, "RDMA Write completion failed\n"); return 1;
    	}*/
	printf("Done sending\n");
	//////////////
	while(1){
		sleep(10);
	}
	
}
