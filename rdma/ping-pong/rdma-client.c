//gcc -o client rdma-client.c -lrdmacm -libverbs
// Change the Server_addr and port number
#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <stdlib.h>
#include <unistd.h>
#define PORT "9999"
#define BUFFER_SIZE 4096
#define MAX_WR 10
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define SERVER_ADDR "172.31.31.182"
int main(){
	struct rdma_cm_event *event;
        struct rdma_event_channel *ch =  rdma_create_event_channel ();
	 struct rdma_cm_id *id = NULL;
        rdma_create_id (ch, &id, NULL,RDMA_PS_TCP);
	struct addrinfo *dst_addr;
        getaddrinfo(SERVER_ADDR, PORT, NULL, &dst_addr);	
	printf("Before resolve addr Creation\n");
	rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
	printf("Before Get Event\n");
	rdma_get_cm_event(ch, &event);
	printf("Before Ack Event\n");
	rdma_ack_cm_event(event);
	printf("Before route resolve Creation\n");
	rdma_resolve_route(id, 2000);
	rdma_get_cm_event(ch, &event);
	rdma_ack_cm_event(event);
	printf("Before PD Creation\n");
	struct ibv_pd *pd = ibv_alloc_pd(id->verbs);
        char* buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr *mr = ibv_reg_mr(pd, buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        struct ibv_cq *cq = ibv_create_cq(id->verbs, 16, NULL, NULL, 0);
        struct ibv_qp_init_attr attr = {
                                       .send_cq = cq,
                                       .recv_cq = cq,
                                       .qp_type = IBV_QPT_RC,
                                       .cap = {
                                             .max_send_wr = MAX_WR,
                                             .max_recv_wr = MAX_WR,
                                             .max_send_sge = 1,
                                             .max_recv_sge = 1,
                                            },
                                      };
	printf("Before QP Creation\n");
        rdma_create_qp(id, pd, &attr);
        struct ibv_qp *qp = id->qp;
        struct ibv_recv_wr *bad_wr;
        struct ibv_sge sge = {
                .addr = (uintptr_t)buf,
                .length = BUFFER_SIZE,
                .lkey = mr->lkey,
                };
        struct ibv_recv_wr wr = {
                .wr_id = 1,
                .sg_list = &sge,
                .num_sge = 1,
                };
        ibv_post_recv(qp, &wr, &bad_wr);

	struct rdma_conn_param conn_param = {};
	printf("Reached RDMA_CONNECT \n");
        rdma_connect (id, &conn_param);
	printf("Reached RDMA_CONNECT1 \n");
	 rdma_get_cm_event(ch, &event); /* ESTABLISHED */
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
        printf("Connected to server\n");
        //---------------------
        /* ── DATA TRANSFER ───────────────────────────────────── */

	/* 6. SEND a message to the server */
	snprintf(buf, BUFFER_SIZE, "Hello from clientX!");
	
	struct ibv_sge send_sge = {
	.addr = (uintptr_t)buf,
	.length = strlen(buf) + 1,
	.lkey = mr->lkey,
	};
	struct ibv_send_wr send_wr = {
	.wr_id = 20,
	.sg_list = &send_sge,
	.num_sge = 1,
	.opcode = IBV_WR_SEND,
	.send_flags = IBV_SEND_SIGNALED,
	};
	struct ibv_send_wr *bad_send;
	ibv_post_send(qp, &send_wr, &bad_send);
	/////////////////////////

	struct ibv_wc wc;
	while(wc.status != IBV_WC_SUCCESS){
        	ibv_poll_cq(cq, 1, &wc);
	}
	 rdma_get_cm_event(ch, &event); /* ESTABLISHED */
        rdma_ack_cm_event(event);
        printf("Buff On client Side%s \n", buf);	
	rdma_disconnect(id);
        ibv_dereg_mr(mr);
        free(buf);
        ibv_destroy_qp(qp);
        ibv_destroy_cq(cq);
        ibv_dealloc_pd(pd);
        rdma_destroy_id(id);
        rdma_destroy_event_channel(ch);
	
}
