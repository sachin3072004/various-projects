//gcc -o server rdma-server.c -lrdmacm -libverbs
#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <stdlib.h>
#define PORT "9999"
#define BUFFER_SIZE 4096
#define MAX_WR 10
int main(){
	struct rdma_cm_event *event;
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id = NULL;
	rdma_create_id (ch, &id, NULL,RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
        addr.sin_addr.s_addr = INADDR_ANY;
	rdma_bind_addr(id, (struct sockaddr*)&addr);
	int backlog = 10;
	rdma_listen(id, backlog);

	 rdma_get_cm_event(ch, &event);
        if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		fprintf(stderr, "Unexpected event %d\n", event->event);
		exit(1);
	}
        struct rdma_cm_id *client_id = event->id;
        rdma_ack_cm_event(event);
	struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
	char* buf = calloc(1, BUFFER_SIZE);
	struct ibv_mr *mr = ibv_reg_mr(pd, buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	struct ibv_cq *cq = ibv_create_cq(client_id->verbs, 16, NULL, NULL, 0);
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
	rdma_create_qp(client_id, pd, &attr);
	struct ibv_qp *qp = client_id->qp;	
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
	rdma_accept (client_id, &conn_param);
	rdma_get_cm_event(ch, &event);
        printf("Done\n");
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED, got %s %d \n", rdma_event_str(event->event), event->status);
                exit(1);
        }
        rdma_ack_cm_event(event);
        printf("Connection ESTABLISHED\n");
	struct ibv_wc wc;
	while(wc.status != IBV_WC_SUCCESS){
		ibv_poll_cq(cq, 1, &wc);
	}
	printf("Buff OnServer side == %s \n", buf);
	//
	printf("\n Now Hello is sent from the server \n");
	snprintf(buf, BUFFER_SIZE, "Hello from Serv!");

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
	rdma_disconnect(client_id);
	ibv_dereg_mr(mr);
	free(buf);
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	ibv_dealloc_pd(pd);
	rdma_destroy_id(client_id);
	rdma_destroy_id(id);
	rdma_destroy_event_channel(ch);

	
}
