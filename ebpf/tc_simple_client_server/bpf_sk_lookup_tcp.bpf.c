// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>
/* Build a bpf_sock_tuple from the packet. Returns NULL on parse failure. */
static __always_inline struct bpf_sock_tuple *
get_tuple(struct __sk_buff *skb, __u64 *tuple_len, bool *ipv4)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct bpf_sock_tuple *tuple;
    if ((void *)(eth + 1) > data_end)
        return NULL;
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return NULL;
        if (iph->ihl != 5 || iph->protocol != IPPROTO_TCP)
            return NULL;
        tuple      = (struct bpf_sock_tuple *)&iph->saddr;
        *tuple_len = sizeof(tuple->ipv4);
        *ipv4      = true;
    } else {
        return NULL;
    }
    if ((void *)tuple + *tuple_len > data_end)
        return NULL;

    return tuple;
}

SEC("tc")
int drop_if_no_listener(struct __sk_buff *skb)
{
    struct bpf_sock_tuple *tuple;
    struct bpf_sock *sk;
    __u64 tuple_len;
    bool ipv4;

    tuple = get_tuple(skb, &tuple_len, &ipv4);
    if (!tuple)
        return TC_ACT_OK;

    bpf_printk("pkt %pI4:%u -> %pI4:%u",
               &tuple->ipv4.saddr, bpf_ntohs(tuple->ipv4.sport),
               &tuple->ipv4.daddr, bpf_ntohs(tuple->ipv4.dport));

    /* Use skc_ to also match listeners, request socks, time-wait socks. */
    sk = bpf_skc_lookup_tcp(skb, tuple, tuple_len, BPF_F_CURRENT_NETNS, 0);
    if (!sk) {
        bpf_printk("DROP: no socket for this 4-tuple");
        return TC_ACT_SHOT;
    }

    __u32 src_ip = sk->src_ip4;     /* keep network byte order for %pI4 */
    __u32 dst_ip = sk->dst_ip4;
    __u16 src_port = sk->src_port;            /* host order */
    __u16 dst_port = bpf_ntohs(sk->dst_port); /* net order */

    bpf_printk("PASS: sk %pI4:%u state=%d", &src_ip, src_port, sk->state);
    bpf_printk("      peer %pI4:%u", &dst_ip, dst_port);

    bpf_sk_release(sk);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
