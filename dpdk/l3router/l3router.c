#include <stdio.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_common.h>
#include <rte_fib.h>
#include <rte_rcu_qsbr.h>
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
struct rte_fib  *fib;
struct rte_hash *mac_table;
struct rte_mempool *pool;
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

static void create_fib_table(){
	struct rte_fib_conf param = {.type = RTE_FIB_DIR24_8,
					.default_nh = 0,
					.max_routes = 1024,
					 .dir24_8 = {
						.nh_sz  = RTE_FIB_DIR24_8_4B,  /* 4-byte next-hop values  */
						.num_tbl8 = 256,
        					},
					    };
	fib = rte_fib_create("fib",rte_socket_id(), &param);
	uint32_t ip; 
	inet_pton(AF_INET, "192.103.0.0", &ip);
	ip = ntohl(ip);
	rte_fib_add(fib,  ip, 24, 1);
	inet_pton(AF_INET, "192.102.1.0", &ip);
	ip = ntohl(ip);
	rte_fib_add(fib,  ip, 24, 0);
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

struct arp_entry {
uint32_t ip;
struct rte_ether_addr mac;
uint8_t port;
};

// Populated at startup from config
struct arp_entry arp_table[] = {
{
.ip = RTE_IPV4(192,102,1,32),
.mac = {{0x0e,0x06,0xfc,0x9e,0x45,0xd9}},
.port = 0
},
{
.ip = RTE_IPV4(192,102,1,188),
.mac = {{0x0e,0x0e,0x39,0xb7,0x45,0x25}},
.port = 0
},
{
.ip = RTE_IPV4(192,103,0,49),
.mac = {{0x0e,0x97,0x5d,0x8f,0xd0,0x1d}},
.port = 1
},
{
.ip = RTE_IPV4(192,103,0,25),
.mac = {{0x0e,0x43,0x83,0x8c,0x5d,0x15}},
.port = 1
},
};

#define ARP_TABLE_SIZE (sizeof(arp_table) / sizeof(arp_table[0]))

/* Returns pointer to arp_entry on hit, NULL on miss */
static inline struct arp_entry *
arp_lookup(uint32_t dst_ip)
{
    for (uint32_t i = 0; i < ARP_TABLE_SIZE; i++) {
        if (arp_table[i].ip == dst_ip)
            return &arp_table[i];
    }
    return NULL;
}

void edit_mac_address(){
}

void edit_ip_address(){
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
				struct rte_ipv4_hdr* ipv4  = rte_pktmbuf_mtod_offset(pkts_burst[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));
				if(ipv4->next_proto_id == IPPROTO_ICMP){
					char src_buf[INET_ADDRSTRLEN], dst_buf[INET_ADDRSTRLEN];
					inet_ntop(AF_INET, &ipv4->src_addr, src_buf, sizeof(src_buf));
					inet_ntop(AF_INET, &ipv4->dst_addr, dst_buf, sizeof(dst_buf));	
					printf("Src IP %s dst ip %s\n", src_buf, dst_buf);
					uint64_t next_hops[1] = {-1};
					uint32_t ip = ntohl(ipv4->dst_addr);
					uint32_t ips[1] = {ip};
					int result = rte_fib_lookup_bulk(fib, ips, next_hops, 1);

					if(result == 0){
						printf("Next_hops %lu\n", next_hops[0]);	
					}
					printf("TTL %d\n", ipv4->time_to_live);
					//ipv4->time_to_live--;
					struct arp_entry* entry = arp_lookup(ip);
					eth_hdr->dst_addr = entry->mac;
					char buf[RTE_ETHER_ADDR_FMT_SIZE];
					struct rte_ether_addr eth_addr;
					// Retrieve and format the address
					rte_eth_macaddr_get(1, &eth_addr);
					rte_ether_format_addr(buf, sizeof(buf), &eth_addr);
					printf("Port MAC Address: %s\n", buf);

					rte_ether_format_addr(buf, sizeof(buf), &entry->mac );
					printf("Dst MAC Address: %s %ld \n", buf, next_hops[0]);
					struct rte_ether_addr mac_out;
					result = rte_eth_macaddr_get(next_hops[0], &mac_out);
					if(result){
						printf("Failed %d \n ", result);
					}
					eth_hdr->src_addr = mac_out;

					rte_eth_tx_burst(next_hops[0],0,pkts_burst,1 );	

				}
			}
		}
	}
	return 0;
}

void* print_table(){
	while(1){
		uint32_t ip1; 
		char ip1_str[] = "192.103.0.25";
		inet_pton(AF_INET, ip1_str, &ip1);
		ip1 = ntohl(ip1);
		uint32_t ip2; 
		char ip2_str[] = "192.102.1.32";
		inet_pton(AF_INET, ip2_str, &ip2);
		ip2 = ntohl(ip2);
		char* ip_strs[] = {ip1_str, ip2_str};
		uint32_t ips[2] = {ip1, ip2};
		uint64_t next_hops[2];
		int n = 2;
		int result = rte_fib_lookup_bulk(fib, ips, next_hops, n);
		if(result == 0){
			for(int i = 0;i<n;i++){
				printf("IP %s Next Hop %lu \n",ip_strs[i], next_hops[i]);
			}
		}
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
	create_fib_table();
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
