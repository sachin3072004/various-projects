#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#define PORT "9999"
#define BUFFER_SIZE 1024
#define SERVER_ADDRESS "172.31.31.182"

void setup_receive(char* recv_buf, struct ibv_mr *recv_mr,struct ibv_cq *cq, struct ibv_qp *qp ){
        struct ibv_sge recv_sge = {
            .addr   = (uintptr_t)recv_buf, // Pointer to your registered buffer
            .length = BUFFER_SIZE,              // Size of the buffer
            .lkey   = recv_mr->lkey           // Local key from ibv_reg_mr
        };

        struct ibv_recv_wr recv_wr = {
            .wr_id   = 43,               // Custom ID for tracking
            .sg_list = &recv_sge,
            .num_sge = 1
        };

        struct ibv_recv_wr *recv_bad_wr;
        if (ibv_post_recv(qp, &recv_wr, &recv_bad_wr)) {
            fprintf(stderr, "Failed to post receive\n");
		return ;
        }
}

void setup_send(char* send_buf,struct ibv_mr *send_mr,struct ibv_cq *cq,struct ibv_qp *qp, int num ){
	struct ibv_send_wr *send_bad_wr;
	snprintf(send_buf, BUFFER_SIZE, "%d \n", num);
	printf("Send_buf %s\n", send_buf);
	struct ibv_sge send_sge = {
            .addr   = (uintptr_t)send_buf, // Pointer to your registered buffer
            .length = BUFFER_SIZE,              // Size of the buffer
            .lkey   = send_mr->lkey           // Local key from ibv_reg_mr
        };

        struct ibv_send_wr send_wr = {
            .wr_id   = 42,               // Custom ID for tracking
            .next    = NULL,             // Link to next WR if posting multiple
            .sg_list = &send_sge,
	    .num_sge    = 1,
	    .opcode     = IBV_WR_SEND, // Standard Send
	    .send_flags = IBV_SEND_SIGNALED,
        };
	ibv_post_send(qp, &send_wr, &send_bad_wr);
}

void poll(struct ibv_cq *cq){
	int num = 0;
	struct ibv_wc wc = {};
	while(num<=0 || wc.opcode != IBV_WC_RECV){
		num = ibv_poll_cq(cq, 1, &wc);
	}
}

int main(){
        struct rdma_event_channel *chan =  rdma_create_event_channel ();
        struct rdma_cm_id *id;
        rdma_create_id(chan, &id, NULL, RDMA_PS_TCP);
	struct addrinfo *dst_addr;	
	getaddrinfo(SERVER_ADDRESS, PORT, NULL, &dst_addr);
	rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
        struct rdma_cm_event  *event;
        rdma_get_cm_event(chan, &event);
        rdma_ack_cm_event(event);
	rdma_resolve_route(id, 2000);
        rdma_get_cm_event(chan, &event);
        rdma_ack_cm_event(event);
        struct ibv_pd *pd = ibv_alloc_pd(id->verbs);
        if (!pd) {
            fprintf(stderr, "Failed to allocate Protection Domain\n");
            return 1;
        }
        void* recv_buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr *recv_mr = ibv_reg_mr(pd, recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        void* send_buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr *send_mr = ibv_reg_mr(pd, send_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
        struct ibv_cq *cq = ibv_create_cq(id->verbs, 16, NULL, NULL, 0);
        struct ibv_qp_init_attr qp_init_attr = {
                                                    .send_cq = cq,
                                                    .recv_cq = cq,
                                                    .qp_type = IBV_QPT_RC, // Reliable Connected
                                                    .cap = {
                                                        .max_send_wr = 10,
                                                        .max_recv_wr = 10,
                                                        .max_send_sge = 1,
                                                        .max_recv_sge = 1,
                                                    },
                                                };
	rdma_create_qp(id, pd, &qp_init_attr);
	struct ibv_qp *qp = id->qp;
	struct rdma_conn_param conn_param = {};
	setup_receive(send_buf, send_mr, cq, qp);
	rdma_connect (id, &conn_param);
	rdma_get_cm_event(chan, &event); /* ESTABLISHED */
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
        printf("Connected to server\n");
	int counter = 1;
	int num = counter;
	while(counter  + 100 > num){
		setup_send(send_buf, send_mr, cq, qp, num );
		printf("%s\n", send_buf);
		poll(cq);
		printf("Received %s\n", recv_buf);
		setup_receive(recv_buf, recv_mr, cq, qp);
		num += 1;
	}
	sleep(5);
}
