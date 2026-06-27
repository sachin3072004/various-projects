#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <rdma/rdma_cma.h>

#define PORT "9999"
#define BUFFER_SIZE 4096
#define MAX_WR 10

struct conn_info {
    uint64_t addr;   /* remote virtual address of the counter (network byte order via htonll-style packing below) */
    uint32_t rkey;   /* remote key for that memory region */
};

static inline uint64_t htonll_(uint64_t v) {
    return ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL)) << 32) |
           (uint64_t)htonl((uint32_t)(v >> 32));
}
static inline uint64_t ntohll_(uint64_t v) {
    return htonll_(v); /* symmetric */
}

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
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
        addr.sin_addr.s_addr = INADDR_ANY;
	rdma_bind_addr (id, (struct sockaddr *)&addr);
	int backlog = 5;
	rdma_listen (id, backlog);
	struct rdma_cm_event *event;	
	rdma_get_cm_event(ch, &event);
        if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
                fprintf(stderr, "Unexpected event %d\n", event->event);
                exit(1);
        }
        struct rdma_cm_id *client_id = event->id;
        rdma_ack_cm_event(event);
        struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
        //char* send_buf = calloc(1, BUFFER_SIZE);
        char* recv_buf = calloc(1, BUFFER_SIZE);
        struct ibv_mr *recv_mr = ibv_reg_mr(pd, recv_buf, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
        char* buf = calloc(1, BUFFER_SIZE);
	strcpy(buf, "RDMA ONE SIDED READ is working!!!");	
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
        struct ibv_sge recv_sge = {
                .addr = (uintptr_t)recv_buf,
                .length = BUFFER_SIZE,
                .lkey = recv_mr->lkey,
                };
        struct ibv_recv_wr wr = {
                .wr_id = 1,
                .sg_list = &recv_sge,
                .num_sge = 1,
                };
        ibv_post_recv(qp, &wr, &bad_wr);
	struct rdma_conn_param conn_param = {};
	int64_t counter  __attribute__((aligned(8))) = 123;
	struct ibv_mr *counter_mr = ibv_reg_mr(pd, &counter, sizeof(counter), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC);
	struct conn_info info;
	info.addr = htonll_((uint64_t)(uintptr_t)&counter);
    	
	info.rkey = htonl(counter_mr->rkey);
	conn_param.private_data = &info;
	conn_param.private_data_len = sizeof(info);
	conn_param.initiator_depth = 1;
        conn_param.responder_resources = 1;
        conn_param.rnr_retry_count = 7;
        rdma_accept (client_id, &conn_param);
        rdma_get_cm_event(ch, &event);
        printf("Done\n");
        if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
                printf("Expected ESTABLISHED, got %s %d \n", rdma_event_str(event->event), event->status);
                exit(1);
        }
        rdma_ack_cm_event(event);
        printf("Connection ESTABLISHED\n");
	////////////////////////////////////////
	//Send server info to client so that client can read and write on server memory
	struct MRInfo mri;
        struct ibv_mr *send_mr = ibv_reg_mr(pd, &mri, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	mri.addr = (uintptr_t)buf;
        mri.key = mr->rkey;
        mri.sz = BUFFER_SIZE;
        mri.id = 12345;
        printf("Sending MRI %p Key %d SZ %d id %d \n", mri.addr, mri.key, mri.sz, mri.id);
	struct ibv_sge send_sge = {0};
        //memset(&sg, 0, sizeof(sg));
        send_sge.addr     = (uintptr_t)&mri;
        send_sge.length = sizeof(struct MRInfo);
        send_sge.lkey     = send_mr->lkey;
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
	///////////////////////
	int n = 0;
	struct ibv_wc wc;
	do {
                     n = ibv_poll_cq(cq, 1, &wc);
                     if(n == 0){
                             continue;
                     }
                     if(wc.opcode == IBV_WC_SEND){
                             break;
                     }
         }while(n == 0);
	printf("\n Server has already sent %d Stored text is %s \n",n, buf);	
	////////////////////////////////////////
	sleep(5);
	printf("Now server contains ==  %s %ld \n", buf,counter);
	while(1){
		sleep(5);
	}

}
