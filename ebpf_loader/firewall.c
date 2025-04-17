#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct rule_key {
    __u32 src_ip;
    __u16 dest_port;
    __u8  proto;
    __u8  pad;
};

struct event_t {
    __u32 src_ip;
    __u16 dest_port;
    __u8  proto;
    __u8  allowed;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rule_key);
    __type(value, __u8);
    __uint(max_entries, 1024);
} rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

static __always_inline void log_event(struct xdp_md *ctx, __u32 src_ip, __u16 dest_port, __u8 proto, __u8 allowed) {
    struct event_t evt = {
        .src_ip = src_ip,
        .dest_port = dest_port,
        .proto = proto,
        .allowed = allowed
    };
    bpf_printk("XDP src=0x%x port=%u proto=%u\n", src_ip, dest_port, proto);
    bpf_printk(" -> allowed=%u\n", allowed);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
}

SEC("xdp")
int xdp_firewall_prog(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    __u8 proto = iph->protocol;

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(iph + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_PASS;
        __u16 dport = bpf_ntohs(tcp->dest);
        struct rule_key k = {.src_ip = iph->saddr, .dest_port = dport, .proto = IPPROTO_TCP};
        __u8 *val = bpf_map_lookup_elem(&rules, &k);
        __u8 allowed = val && (*val == 1);
        log_event(ctx, k.src_ip, dport, k.proto, allowed);
        return allowed ? XDP_PASS : XDP_DROP;
    }

    if (proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(iph + 1);
        if ((void *)(udp + 1) > data_end) return XDP_PASS;
        __u16 dport = bpf_ntohs(udp->dest);
        struct rule_key k = {.src_ip = iph->saddr, .dest_port = dport, .proto = IPPROTO_UDP};
        __u8 *val = bpf_map_lookup_elem(&rules, &k);
        __u8 allowed = val && (*val == 1);
        log_event(ctx, k.src_ip, dport, k.proto, allowed);
        return allowed ? XDP_PASS : XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
