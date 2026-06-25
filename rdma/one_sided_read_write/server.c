#include <stdio.h>
#include <rdma/rdma_cma.h>

int main(){
	struct rdma_event_channel *channel = rdma_create_event_channel ();
	struct rdma_cm_id id;
	rdma_create_id(channel, &id, NULL, RDMA_PS_TCP);
	struct sockaddr_in addr = {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(PORT));
        addr.sin_addr.s_addr = INADDR_ANY;
        rdma_bind_addr(id, (struct sockaddr*)&addr);
	int backlog = 5;
	rdma_listen(&id, backlog);
}
