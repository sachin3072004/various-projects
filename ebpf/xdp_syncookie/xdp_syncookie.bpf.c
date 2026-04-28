// syncookie_xdp.c
// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DEFAULT_MSS4   1460
#define DEFAULT_MSS6   1440
#define DEFAULT_WSCALE 7
#define DEFAULT_TTL    64

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} listen_socks SEC(".maps");

/* Counters for observability */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

enum { STAT_SYN_COOKIES_SENT, STAT_ACK_VALIDATED, STAT_ACK_REJECTED, STAT_PASSED };

static __always_inline void bump(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) (*v)++;
}

static __always_inline void csum_replace4(__u16 *csum, __u32 old, __u32 new)
{
    __u32 c = ~bpf_ntohs(*csum) & 0xffff;
    c += (~old >> 16) & 0xffff;
    c += (~old) & 0xffff;
    c += (new >> 16) & 0xffff;
    c += new & 0xffff;
    c = (c & 0xffff) + (c >> 16);
    c = (c & 0xffff) + (c >> 16);
    *csum = bpf_htons(~c & 0xffff);
}

static __always_inline void csum_replace2(__u16 *csum, __u16 old, __u16 new)
{
    __u32 c = ~bpf_ntohs(*csum) & 0xffff;
    c += (~old) & 0xffff;
    c += new;
    c = (c & 0xffff) + (c >> 16);
    c = (c & 0xffff) + (c >> 16);
    *csum = bpf_htons(~c & 0xffff);
}

/* Swap L2/L3/L4 addresses so we can reflect the SYN-ACK back. */
static __always_inline void swap_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_ipv4(struct iphdr *ip)
{
    __be32 tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

static __always_inline void swap_ports(struct tcphdr *th)
{
    __be16 tmp = th->source;
    th->source = th->dest;
    th->dest = tmp;
}

static __always_inline int write_synack_opts(void *opts, void *data_end, __u16 mss)
{
    __u8 *p = opts;
    if (p + 12 > (__u8 *)data_end)
        return -1;

    p[0] = 2; p[1] = 4;
    *(__be16 *)(p + 2) = bpf_htons(mss);
    p[4] = 1; p[5] = 1;
    p[6] = 4; p[7] = 2;
    p[8] = 1;
    p[9] = 3; p[10] = 3; p[11] = DEFAULT_WSCALE;
    return 12;
}

SEC("xdp")
int syncookie_xdp(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS; /* IPv6 path omitted for brevity; structure is identical */

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* Bounds-check variable IP header length */
    if (ip->ihl < 5)
        return XDP_PASS;
    __u32 iphlen = ip->ihl * 4;
    if ((void *)ip + iphlen + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    struct tcphdr *th = (void *)ip + iphlen;

    /* -------- SYN path: generate cookie, rewrite into SYN-ACK -------- */
    if (th->syn && !th->ack && !th->rst && !th->fin) {
        /* Look up the listen sock we're protecting */
        struct bpf_sock_tuple tup = {
            .ipv4.saddr = ip->saddr,
            .ipv4.daddr = ip->daddr,
            .ipv4.sport = th->source,
            .ipv4.dport = th->dest,
        };

        struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tup, sizeof(tup.ipv4),
                                                 BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return XDP_PASS;

        /* Only intervene if there's a listener in TCP_LISTEN for this 4-tuple */
        if (sk->state != BPF_TCP_LISTEN) {
            bpf_sk_release(sk);
            return XDP_PASS;
        }

        /* Ask the kernel for a cookie. Returns the ISN to put in seq field. */
        __s64 cookie = bpf_tcp_gen_syncookie(sk, ip, sizeof(*ip),
                                             th, sizeof(*th) /* opts len of 0 is fine */);
	bpf_printk("Cookie %ld \n", cookie);
        bpf_sk_release(sk);
        if (cookie < 0)
            return XDP_PASS; /* Helper refused — bad packet, let stack decide */

        /* Remember old header fields for checksum delta */
        __u32 old_saddr = ip->saddr;
        __u32 old_daddr = ip->daddr;
        __u16 old_tot_len = ip->tot_len;
        __u8  old_ttl_proto_hi = ((__u8 *)ip)[8]; /* TTL/protocol word, for IP csum */

        __u32 old_seq = th->seq;
        __u32 old_ack = th->ack_seq;
        /* flag word: data offset (4b) + reserved (4b) + flags (8b) = 16 bits */
        __u16 old_flag_word = *((__u16 *)th + 6);

        /* Reflect addresses / ports */
        swap_mac(eth);
        swap_ipv4(ip);
        swap_ports(th);

        /* SYN-ACK: seq = cookie, ack = client_seq + 1 */
        __u32 client_isn = bpf_ntohl(th->seq); /* th->seq still holds original after port swap */
        th->seq     = bpf_htonl((__u32)cookie);
        th->ack_seq = bpf_htonl(client_isn + 1);

        /* Set flags: SYN=1, ACK=1, everything else clear. Preserve doff. */
        th->syn = 1;
        th->ack = 1;
        th->fin = 0; th->rst = 0; th->psh = 0; th->urg = 0; th->ece = 0; th->cwr = 0;

        /* Write TCP options. We need to grow the header from 20 -> 32 bytes.
         * Using bpf_xdp_adjust_tail if the frame isn't already big enough.
         * For typical SYNs (60 bytes with opts) this is a no-op — we just
         * overwrite the client's options area. */
        int opts_len = 12;
        int new_doff = (sizeof(struct tcphdr) + opts_len) / 4;

        /* Make sure there's room in the packet for 20 + 12 TCP bytes.
         * Original SYN usually carried >=12 bytes of options already. */
        __u8 *opts = (__u8 *)(th + 1);
        if (opts + opts_len > (__u8 *)data_end) {
            /* Rare: SYN with no options. Drop rather than fix up length here. */
            return XDP_DROP;
        }
        if (write_synack_opts(opts, data_end, DEFAULT_MSS4) < 0)
            return XDP_DROP;

        th->doff = new_doff;

        /* IP: restore TTL, nothing else changes size */
        ip->ttl = DEFAULT_TTL;

        /* --- Recompute IP checksum incrementally --- */
        ip->check = 0;
        {
            __u32 sum = 0;
            __u16 *p = (__u16 *)ip;
            #pragma unroll
            for (int i = 0; i < 10; i++) sum += p[i];
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            ip->check = ~sum;
        }

        /* --- Recompute TCP checksum from scratch over the (small) header ---
         * Pseudo-header: saddr, daddr, 0, proto, tcp_len */
        th->check = 0;
        {
            __u32 sum = 0;
            __u16 tcp_len = sizeof(*th) + opts_len;

            /* pseudo */
            sum += (ip->saddr >> 16) & 0xffff;
            sum += ip->saddr & 0xffff;
            sum += (ip->daddr >> 16) & 0xffff;
            sum += ip->daddr & 0xffff;
            sum += bpf_htons(IPPROTO_TCP);
            sum += bpf_htons(tcp_len);

            /*__u16 *p = (__u16 *)th;
            #pragma unroll
            for (int i = 0; i < 16; i++) {
                if ((void *)p + (i + 1) * 2 > data_end) return XDP_DROP;
                sum += p[i];
            }*/
	    __u16 *p = (__u16 *)th;
		if ((void *)p + 32 > data_end)
			return XDP_DROP;

	#pragma unroll
	for (int i = 0; i < 16; i++)
		sum += p[i];
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            th->check = ~sum;
        }

        /* Silence unused warnings from the delta-update path we didn't take */
        (void)old_saddr; (void)old_daddr; (void)old_tot_len;
        (void)old_ttl_proto_hi; (void)old_seq; (void)old_ack; (void)old_flag_word;

        bump(STAT_SYN_COOKIES_SENT);
        return XDP_TX;
    }

    /* -------- ACK path: validate cookie, pass up if good -------- */
    if (th->ack && !th->syn && !th->rst && !th->fin) {
        struct bpf_sock_tuple tup = {
            .ipv4.saddr = ip->saddr,
            .ipv4.daddr = ip->daddr,
            .ipv4.sport = th->source,
            .ipv4.dport = th->dest,
        };

        /* Only bother validating if no established sock matches already —
         * otherwise this is normal data and we just pass. */
        struct bpf_sock *sk = bpf_skc_lookup_tcp(ctx, &tup, sizeof(tup.ipv4),
                                                 BPF_F_CURRENT_NETNS, 0);
        if (!sk) {
            bump(STAT_PASSED);
            return XDP_PASS;
        }

        if (sk->state != BPF_TCP_LISTEN) {
            /* Existing flow — let the stack handle it. */
            bpf_sk_release(sk);
            bump(STAT_PASSED);
            return XDP_PASS;
        }

        /* No request_sock exists (we never allocated one). Check cookie. */
        __s64 rc = bpf_tcp_check_syncookie(sk, ip, sizeof(*ip), th, sizeof(*th));
        bpf_sk_release(sk);

        if (rc == 0) {
            /* Valid cookie. Pass up — the stack will create a real socket
             * via its own cookie-check fallback (TFO-style) when the packet
             * arrives with no matching req_sock. */
            bump(STAT_ACK_VALIDATED);
            return XDP_PASS;
        }

        bump(STAT_ACK_REJECTED);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
