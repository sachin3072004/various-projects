#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <unistd.h>
#include <stdlib.h>
#define PORT "9999"
#define BUFFER_SIZE 1024
struct rdma_event_channel *chan;
struct ibv_comp_channel *shared_channel = NULL;

struct ibv_srq* create_srq(struct ibv_pd *pd){
        struct ibv_srq_init_attr srq_attr = {
                .attr = {
                        .max_wr = 10,
                        .max_sge = 1,
                },
        };
        struct ibv_srq* srq = ibv_create_srq(pd, &srq_attr);
	return srq;
}

void setup_send_buf(char* send_buf, struct ibv_mr* send_mr, struct ibv_qp *qp, int received_num){
	struct ibv_send_wr *send_bad_wr;
        snprintf(send_buf, BUFFER_SIZE, "%d \n", received_num+1);
	printf("Server trying to send Buffer %s \n", send_buf);
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
        int ret = ibv_post_send(qp, &send_wr, &send_bad_wr);
	if (ret != 0) {
	    // Failure in posting (e.g., Queue Pair full, or malformed Work Request)
	    // 'bad_wr' points to the specific Work Request that failed
	    fprintf(stderr, "Failed to post send: %s\n", strerror(ret));
	}
}

void setup_recv_buf(char* recv_buf, struct ibv_mr* recv_mr,struct ibv_qp *qp, struct ibv_srq* srq){
	struct ibv_sge recv_sge = {
	    .addr   = (uintptr_t)recv_buf, // Pointer to your registered buffer
	    .length = BUFFER_SIZE,              // Size of the buffer
	    .lkey   = recv_mr->lkey           // Local key from ibv_reg_mr
	};

	struct ibv_recv_wr recv_wr = {
	    .wr_id   = 42,               // Custom ID for tracking
	    .next    = NULL,             // Link to next WR if posting multiple
	    .sg_list = &recv_sge,
	    .num_sge = 1
	};

	struct ibv_recv_wr *bad_wr;
	if (ibv_post_srq_recv(srq, &recv_wr, &bad_wr)) {
	//if (ibv_post_recv(qp, &recv_wr, &bad_wr)) {
	    fprintf(stderr, "Failed to post receive\n");
	}
}

void poll_cq(struct ibv_cq *cq, void* recv_buf,struct ibv_mr *recv_mr , void* send_buf, struct ibv_mr *send_mr, struct ibv_qp *qp, struct ibv_srq* srq){
        int num = 0;
        struct ibv_wc wc = {};
        while(num<=0 || wc.opcode != IBV_WC_RECV){
                num = ibv_poll_cq(cq, 1, &wc);
        }

	printf("Received from Client: %s \n", recv_buf);
	setup_recv_buf(recv_buf, recv_mr, qp, srq);
	int receivedToken = atoi(recv_buf);
	//if (receivedToken == -1){
	//	break;
	//}
	snprintf(send_buf, BUFFER_SIZE, "%d", receivedToken + 1);
	setup_send_buf(send_buf, send_mr, qp, receivedToken);
	printf("Sent SuccessFul \n");

}

void poll_shared_completion_channel(void* recv_buf,struct ibv_mr *recv_mr , void* send_buf, struct ibv_mr *send_mr, struct ibv_qp *qp, struct ibv_srq* srq){
        while (1) {
                struct ibv_cq *ev_cq;
                void *ev_ctx;
		printf("Shared_channel %p\n", shared_channel);
                if (ibv_get_cq_event(shared_channel, &ev_cq, &ev_ctx)) {
                        fprintf(stderr, "ibv_get_cqe_event failed\n");
                        break;
                }
		printf("Got an event");
                ibv_ack_cq_events(ev_cq, 1);

                if (ibv_req_notify_cq(ev_cq, 0)) {
                        fprintf(stderr, "Failed to re-arm CQ\n");
                        break;
                }
		printf("Poll_CQ == %p \n", ev_cq);
                poll_cq(ev_cq, recv_buf, recv_mr , send_buf, send_mr, qp, srq);
        }
}


void poll(struct ibv_cq *cq){
	int num = 0;
        struct ibv_wc wc = {};
        while(num<=0 || wc.opcode != IBV_WC_RECV){
                num = ibv_poll_cq(cq, 1, &wc);
        }
}

void* handle_client_connection(void* client)
{
	struct rdma_cm_id *client_id = client;
	struct rdma_cm_event  *event;
	struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
	if (!pd) {
	    fprintf(stderr, "Failed to allocate Protection Domain\n");
	    return NULL;
	}
	struct ibv_srq* srq = create_srq(pd);
	void* recv_buf = calloc(1, BUFFER_SIZE);
	struct ibv_mr *recv_mr = ibv_reg_mr(pd, recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);	
	void* send_buf = calloc(1, BUFFER_SIZE);
	struct ibv_mr *send_mr = ibv_reg_mr(pd, send_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);	
	struct ibv_cq *cq = ibv_create_cq(client_id->verbs, 16,NULL, shared_channel, 0);
	ibv_req_notify_cq(cq, 0);
	struct ibv_qp_init_attr qp_init_attr = {
						    .send_cq = cq,
						    .recv_cq = cq,
						    .qp_type = IBV_QPT_RC, // Reliable Connected
						    .srq = srq,
						    .cap = {
							.max_send_wr = 10,
							.max_recv_wr = 0,
							.max_send_sge = 1,
							.max_recv_sge = 1,
						    },
						};
	rdma_create_qp(client_id, pd, &qp_init_attr);
	struct ibv_qp *qp = client_id->qp;
	setup_recv_buf(recv_buf, recv_mr, qp, srq);
	struct rdma_conn_param conn_param = {};
	rdma_accept(client_id, &conn_param);
	while(1){
		int num = 0;
		poll_shared_completion_channel(recv_buf, recv_mr, send_buf, send_mr, qp, srq);
	
		//poll(cq);
		/*printf("Received from Client: %s \n", recv_buf);
		setup_recv_buf(recv_buf, recv_mr, qp);
		int receivedToken = atoi(recv_buf);
		if (receivedToken == -1){
			break;
		}
		snprintf(send_buf, BUFFER_SIZE, "%d", receivedToken + 1);
		setup_send_buf(send_buf, send_mr, qp, receivedToken);
		printf("Sent SuccessFul \n");*/
	}
		
}

int totalThreads = 1000;
int main(){
	chan =  rdma_create_event_channel ();
	struct rdma_cm_id *id;
	rdma_create_id(chan, &id, NULL, RDMA_PS_TCP);
	
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
        addr.sin_addr.s_addr = INADDR_ANY;
        rdma_bind_addr (id, (struct sockaddr *)&addr);	
	int backlog = 5;
	pthread_t threads[totalThreads];
	int threadNum = 0;
	rdma_listen(id, backlog);
	while(threadNum < totalThreads){
		struct rdma_cm_event  *event;
		rdma_get_cm_event(chan, &event);
		if(event->event != RDMA_CM_EVENT_CONNECT_REQUEST){
			printf("Expected RDMA_CM_EVENT_CONNECT_REQUEST Received %s \n", rdma_event_str(event->event));
			continue;
		} 
		struct rdma_cm_id *client_id = event->id;
		rdma_ack_cm_event(event);			
		if (!shared_channel){
			shared_channel = ibv_create_comp_channel(client_id->verbs);
		}
		pthread_create(&threads[threadNum], NULL, handle_client_connection, client_id);
		threadNum += 1;
	}
	for(int i = 0;i<totalThreads;i++){
		pthread_join(threads[i], NULL);
	}
}
