#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
char licensei1[] SEC("license") = "GPL";

struct xmit_packet{
	__u16 common_type;     
       	__u8 common_flags;      
        __u8 common_preempt_count;     
        __u32 common_pid; 

        void * skbaddr;        
        __u32 len;      
        __u32 rc;        
        __u32 name;  
};

struct EthHdr{
	__u8 dstMac[6];
	__u8 srcMac[6];
	__be16 ethType;

}__attribute__((packed));

struct IPV4Hdr {
	__u32 phaltu[3];
	__u8 srcIp[4];
	__u8 dstIp[4];
};

struct L4Hdr {
	__u16 srcPort;
	__u16 dstPort;
};

SEC("tracepoint/net/net_dev_xmit")
int catch_packet(struct xmit_packet *pkt) {
	struct sk_buff* skb = (struct sk_buff*)pkt->skbaddr;
	unsigned char *ptr = BPF_CORE_READ(skb,head);

	__u16 mac_header = BPF_CORE_READ(skb,mac_header);
	bpf_printk("head=0x%llx mac_header=%u\n", (__u64)ptr, mac_header);
	struct EthHdr ethHdr;
	bpf_probe_read_kernel(&ethHdr, sizeof(struct EthHdr), (ptr + mac_header));
	__u16 proto = bpf_ntohs(ethHdr.ethType);
	bpf_printk("Src Value: %x %x %x %x %x %x \n", (__u64)ethHdr.srcMac[0], (__u64)ethHdr.srcMac[1], (__u64)ethHdr.srcMac[2], (__u64)ethHdr.srcMac[3], (__u64)ethHdr.srcMac[4], (__u64)ethHdr.srcMac[5]);
	bpf_printk("Dst Value: %x %x %x %x %x %x \n", (__u64)ethHdr.dstMac[0], (__u64)ethHdr.dstMac[1], (__u64)ethHdr.dstMac[2], (__u64)ethHdr.dstMac[3], (__u64)ethHdr.dstMac[4], (__u64)ethHdr.dstMac[5]);
	bpf_printk("Protocol: %x \n", proto);
	struct IPV4Hdr ipv4Hdr;
	bpf_probe_read_kernel(&ipv4Hdr, sizeof(struct IPV4Hdr), (ptr + mac_header + sizeof(struct EthHdr)));
	bpf_printk("Src IP: %u %u %u %u\n", (__u64)ipv4Hdr.srcIp[0], (__u64)ipv4Hdr.srcIp[1], (__u64)ipv4Hdr.srcIp[2], (__u64)ipv4Hdr.srcIp[3]);
	bpf_printk("Dst IP: %u %u %u %u\n", (__u64)ipv4Hdr.dstIp[0], (__u64)ipv4Hdr.dstIp[1], (__u64)ipv4Hdr.dstIp[2], (__u64)ipv4Hdr.dstIp[3]);
	struct L4Hdr l4hdr;
	bpf_probe_read_kernel(&l4hdr, sizeof(struct L4Hdr), (ptr + mac_header + sizeof(struct EthHdr) + sizeof(struct IPV4Hdr)));
	__u16 srcPort = bpf_ntohs(l4hdr.srcPort);
	__u16 dstPort = bpf_ntohs(l4hdr.dstPort);
	bpf_printk("SrcPort  %d DstPort %d \n", srcPort, dstPort);
	return 0;
}
