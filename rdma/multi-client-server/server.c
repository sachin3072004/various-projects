#include <stdio.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#define BUFFER_SIZE 4096
#define PORT "9999"

int main(){
	struct rdma_event_channel *ch =  rdma_create_event_channel ();
	struct rdma_cm_id *id,*client_id;
	rdma_create_id(ch, &id, NULL, RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
	char* specific_ip_address = "172.31.31.182";
        addr.sin_addr.s_addr = inet_addr(specific_ip_address);;
	printf("Id == %p\n",id);	
	rdma_bind_addr (id, (struct sockaddr*)&addr);
	int backlog = 10;
	rdma_listen(id, backlog);
	struct rdma_cm_event *event;
	rdma_get_cm_event (ch, &event);
	client_id = event->id;
	rdma_ack_cm_event (event);	
	struct ibv_pd *pd = ibv_alloc_pd(client_id->verbs);
	char* recv_buffer = calloc(1, BUFFER_SIZE);
	struct ibv_mr *recv_mr = ibv_reg_mr(pd, recv_buffer, BUFFER_SIZE, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ);
	struct ibv_cq *cq = ibv_create_cq(client_id->verbs, 16, NULL, NULL, 0);
	struct ibv_qp_init_attr qp_init_attr;
	qp_init_attr.send_cq = cq; // Previously created
	qp_init_attr.recv_cq = cq; // Previously created
	qp_init_attr.qp_type = IBV_QPT_RC;
	qp_init_attr.cap.max_send_wr = 10;
	qp_init_attr.cap.max_recv_wr = 10;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	rdma_create_qp (client_id, pd, &qp_init_attr);
	struct rdma_conn_param conn_param = {};
	rdma_accept (client_id, &conn_param);
	while(1){
		sleep(10);
	}		
	
}
