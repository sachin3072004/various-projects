#include <stdio.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_ethdev.h>
#include <rte_timer.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#define RX_RING_SIZE    1024
#define TX_RING_SIZE    1024
#define MEMPOOL_SIZE    8191
#define MBUF_CACHE_SIZE 256
#define BURST_SIZE      32
#define NUM_PORTS       2
#define GRE_PROTOCOL    47
struct rte_mempool *pool;
struct rte_hash *mac_table;

struct Key {
	struct rte_ether_addr mac;
};

struct Value {
	uint16_t port;
	uint64_t last_seen;
};

int cores_recv_port[3] = {0,0,1};
struct rte_hash *table;
static const struct rte_eth_conf port_conf = {
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_NONE,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

static void create_mac_table(){
	struct rte_hash_parameters param = {.name = "Sachin",
					    .entries =  1024,
					    .key_len = sizeof(struct Key),
					    .hash_func = rte_jhash,
					    .socket_id = rte_socket_id(),
					    .extra_flag =  RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF};
	table = rte_hash_create(&param);
}

static int initialize_port(int port){
	 uint16_t nb_rxq = 1;
         uint16_t nb_txq = 1;
         rte_eth_dev_configure(port, nb_rxq, nb_txq, &port_conf);	
	 rte_eth_rx_queue_setup(port, 0, RX_RING_SIZE,
                                 rte_eth_dev_socket_id(port),
                                 NULL, pool);
	 rte_eth_tx_queue_setup(port, 0, TX_RING_SIZE,
                                 rte_eth_dev_socket_id(port),
                                 NULL);
	 rte_eth_dev_start(port);
	 printf("Initialize Port %d\n", port);
	 return 0;
}

static int lcore_worker(void* args){
	uint64_t hz = rte_get_timer_hz();
	struct rte_mbuf *pkts_burst[BURST_SIZE];
	while(1){
		int pkt_recv = rte_eth_rx_burst(cores_recv_port[rte_lcore_id()], 0, pkts_burst, BURST_SIZE);
		for(int i = 0; i < pkt_recv; i++){
			struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(pkts_burst[i], struct rte_ether_hdr *);
			uint16_t eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
			if (eth_type == RTE_ETHER_TYPE_IPV4) {
				struct rte_ipv4_hdr* outer_ipv4  = rte_pktmbuf_mtod_offset(pkts_burst[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
				if(outer_ipv4->next_proto_id == IPPROTO_ICMP){
					struct rte_ether_hdr *eth = rte_pktmbuf_mtod(pkts_burst[i], struct rte_ether_hdr *);
					struct Key src_key = {
						.mac = eth->src_addr,
					};
					struct Value v = {
						.port = cores_recv_port[rte_lcore_id()],
						.last_seen = rte_get_timer_cycles()
					};
					int ret = rte_hash_add_key_data(table, &src_key, &v);
					if(ret == 0){
						printf("XXXXXXX Mac Address has been added\n");
					}
				}
				if(outer_ipv4->next_proto_id == IPPROTO_GRE){
					printf("RTE_LCORE_ID %d\n", rte_lcore_id());
					struct rte_ether_hdr *eth = rte_pktmbuf_mtod_offset(pkts_burst[i], struct rte_ether_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_gre_hdr));
					struct Key src_key = {
						.mac = eth->src_addr,
					};
					struct Value v = {
						.port = cores_recv_port[rte_lcore_id()],
						.last_seen = rte_get_timer_cycles()
					};
					int ret = rte_hash_add_key_data(table, &src_key, &v);
					printf("YYY Mac address added \n");
					rte_pktmbuf_adj(pkts_burst[i], sizeof(struct rte_ether_hdr) +  sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_gre_hdr));
					struct rte_ether_hdr *eth1 = rte_pktmbuf_mtod(pkts_burst[i], struct rte_ether_hdr *);
					struct Value *val;
					int result = rte_hash_lookup_data(table, &eth1->dst_addr, (void**)(&val));
					printf("Result %d\n", result);
					if(result >0 ){
						printf("Unicasting REsult Port %d \n", val->port);
					}else{
						uint16_t port;
						RTE_ETH_FOREACH_DEV(port){
							uint16_t in_port = cores_recv_port[rte_lcore_id()];
							if(port != in_port){
								continue;
							}
							printf("Broadcasting Sending to Port %d core %d pkt_recv %d \n", port, rte_lcore_id(), pkt_recv);
							struct rte_mbuf *clone = rte_pktmbuf_clone(pkts_burst[i], pool);
    							if (clone){
								int ret = rte_eth_tx_burst(cores_recv_port[rte_lcore_id()], 0, &clone, 1);
								printf("Ret %d\n", ret);
							}
							struct rte_ipv4_hdr* outer_ipv4 = rte_pktmbuf_mtod_offset(clone, struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
							rte_be32_t src_ip = outer_ipv4->src_addr;
							char src_buf[50];
							if (inet_ntop(AF_INET, &src_ip, src_buf, sizeof(src_buf))) {
    								printf("Src IP Address: %s\n", src_buf);
							}
							rte_be32_t dst_ip = outer_ipv4->dst_addr;
							char dst_buf[50];
							if (inet_ntop(AF_INET, &dst_ip, dst_buf, sizeof(dst_buf))) {
    								printf("Dst IP Address: %s\n", dst_buf);
							}
							struct rte_ether_hdr *eth = rte_pktmbuf_mtod(clone, struct rte_ether_hdr *);
							char src_mac[RTE_ETHER_ADDR_FMT_SIZE];
							char dst_mac[RTE_ETHER_ADDR_FMT_SIZE];
							rte_ether_format_addr(src_mac, sizeof(src_mac), &eth->src_addr);
							rte_ether_format_addr(dst_mac, sizeof(dst_mac), &eth->dst_addr);
							printf("SRC_MAC %s DST_MAC %s \n", src_mac, dst_mac);
						}
						rte_pktmbuf_free(pkts_burst[i]);
					}
				}
			}
		}
	}
	return 0;
}

void* print_table(){
	while(1){
		uint32_t iter = 0;
		void* key;
		void* data;
		int ret;
		printf("\n ----------Mac Table------------ \n");
		while((ret = rte_hash_iterate(table, (const void**)&key, &data, &iter)) >=0){
			char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(mac_addr, sizeof(mac_addr), &((struct Key*)key)->mac);
			printf("Mac_addr == %s %d %lu \n", mac_addr, ((struct Value*)data)->port, ((struct Value*)data)->last_seen);
		}
		printf("\n ----------- \n");
		sleep(5);
	}
	return NULL;
}

int main(int argc, char** argv){
	int ret = rte_eal_init(argc, argv);
	if(ret < 0){
		printf("RTE_EAL_INIT FAILED \n");
	}
	pool = rte_pktmbuf_pool_create("MBUF_POOL", MEMPOOL_SIZE, MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	uint16_t port;
	RTE_ETH_FOREACH_DEV(port){
		initialize_port(port);
	}
	printf("Ports are  initialized \n");
	uint16_t lcore;
	struct rte_timer mytimer;
        rte_timer_init(&mytimer);
	create_mac_table();
	uint16_t port1;
	RTE_ETH_FOREACH_DEV(port1) {
		struct rte_ether_addr mac_addr;
		int ret = rte_eth_macaddr_get(port1, &mac_addr);
		char mac_str[RTE_ETHER_ADDR_FMT_SIZE];
		rte_ether_format_addr(mac_str, sizeof(mac_str), &mac_addr);
		printf("Port %u MAC: %s\n", port1, mac_str);
	}
	RTE_LCORE_FOREACH_WORKER(lcore){
		rte_eal_remote_launch(&lcore_worker, NULL, lcore);
	}
	pthread_t t1;
	pthread_create(&t1, NULL, print_table, NULL );
	pthread_join(t1, NULL);
	rte_eal_mp_wait_lcore();
	RTE_ETH_FOREACH_DEV(port){
		rte_eth_dev_stop(port);
		rte_eth_dev_close(port);
	}
	printf("Prst are closed \n");
	rte_eal_cleanup();
}
