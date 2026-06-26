#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>    
#include <sys/socket.h> 
#include <netdb.h> 
#include <rdma/rdma_cma.h>
#include <unistd.h>
#include <assert.h>
#define PORT "9999"
#define SERVER_ADDR "172.31.31.182"
#define BUFFER_SIZE 4096
#define MAX_WR 10

struct MRInfo{
        uint64_t addr;
        uint32_t sz;
        uint32_t key;
        uint32_t id;
};

int main(){
        struct rdma_event_channel *ch =  rdma_create_event_channel ();
        struct rdma_cm_id *id;
        rdma_create_id (ch, &id, NULL, RDMA_PS_TCP);
	struct addrinfo *dst_addr;
        getaddrinfo(SERVER_ADDR, PORT, NULL, &dst_addr);
	int result = rdma_resolve_addr(id, NULL, dst_addr->ai_addr, 2000);
	printf("Result %d \n", result);
	struct rdma_cm_event *event;
        rdma_get_cm_event (ch, &event);
        rdma_ack_cm_event(event);
	rdma_resolve_route(id, 2000);	
	rdma_get_cm_event (ch, &event);
        rdma_ack_cm_event(event);
	struct ibv_pd *pd;
 	pd = ibv_alloc_pd(id->verbs);
	char* recv_buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr *mr = ibv_reg_mr(pd, recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
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
                .addr = (uintptr_t)recv_buf,
                .length = BUFFER_SIZE,
                .lkey = mr->lkey,
                };
	
        struct ibv_recv_wr wr = {
                .wr_id = 1,
                .sg_list = &sge,
                .num_sge = 1,
                };
        int ret = ibv_post_recv(qp, &wr, &bad_wr);
	if(ret){
		 fprintf(stderr, "Failed to post receive WR. Error: %d\n", ret);
	}
	struct rdma_conn_param conn_param = {};
	conn_param.initiator_depth = 1;
        conn_param.responder_resources = 1;
        conn_param.rnr_retry_count = 7;
        printf("Reached RDMA_CONNECT \n");
        rdma_connect (id, &conn_param);
	rdma_get_cm_event(ch, &event); /* ESTABLISHED */
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED %s \n", rdma_event_str(event->event));
        }
        rdma_ack_cm_event(event);
        printf("Connected to server\n");
        //---------------------
	int n = 0;
        struct ibv_wc wc = {};
        int num_entries = 1;
        do {
                n = ibv_poll_cq(cq, num_entries, &wc);
		sleep(1);
		printf("WC. OPCOde == %d %d\n", wc.opcode);
                if(n <= 0){
                        continue;
                }
                if(wc.opcode == IBV_WC_RECV){
                        break;
                }
		printf("WC. OPCOde == %d\n",ibv_wc_status_str(wc.status));
        }while(n == 0);	
	struct MRInfo *mriinfo = (struct MRInfo*)recv_buf;
        printf("Addr %p key %d sz %d id %d \n", mriinfo->addr,mriinfo->key, mriinfo->sz, mriinfo->id);
	void* send_buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr* send_mr = ibv_reg_mr( pd, send_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        struct ibv_sge sge_write = {
                        .addr = (uintptr_t)send_buf,
                        .length = mriinfo->sz,
                        .lkey = send_mr->lkey
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
        printf("Trying to read from remote\n")  ;
        if (ibv_post_send(id->qp, &swr, &bad_swr)) perror("ibv_post_send write");
        do {
                n = ibv_poll_cq(cq, 1, &wc);
                if(n == 0){
                        continue;
                }
                if(wc.opcode == IBV_WC_RDMA_READ){
                        break;
                }
        }while(n == 0);
        printf("Buf %s\n", send_buf);
        while(1){
                sleep(5);
        }	
}
