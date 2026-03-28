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
				printf("next_proto_id %d \n", outer_ipv4->next_proto_id);
				if(outer_ipv4->next_proto_id == IPPROTO_ICMP){
					 struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(pkts_burst[i],
        struct rte_icmp_hdr *,
        sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

    // Only reply to echo requests (type 8)
    if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
        rte_pktmbuf_free(pkts_burst[i]);
        continue;
    }

    // --- Swap Ethernet MACs ---
    struct rte_ether_addr tmp_mac = eth_hdr->src_addr;
    eth_hdr->src_addr = eth_hdr->dst_addr;
    eth_hdr->dst_addr = tmp_mac;

    // --- Swap IP addresses ---
    rte_be32_t tmp_ip = outer_ipv4->src_addr;
    outer_ipv4->src_addr = outer_ipv4->dst_addr;
    outer_ipv4->dst_addr = tmp_ip;

    // --- Recalculate IP checksum ---
    outer_ipv4->hdr_checksum = 0;
    outer_ipv4->hdr_checksum = rte_ipv4_cksum(outer_ipv4);

    // --- Set ICMP type to echo reply ---
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;

    // --- Recalculate ICMP checksum ---
    icmp->icmp_cksum = 0;
    uint16_t ip_hdr_len = (outer_ipv4->version_ihl & 0x0f) * 4;
    uint16_t icmp_len = rte_be_to_cpu_16(outer_ipv4->total_length) - ip_hdr_len;
    icmp->icmp_cksum = rte_raw_cksum(icmp, icmp_len);

    // --- Send reply out the same port ---
    uint16_t in_port = cores_recv_port[rte_lcore_id()];
    int tx_ret = rte_eth_tx_burst(in_port, 0, &pkts_burst[i], 1);
    if (tx_ret == 0) {
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
