#include "firewall_helpers.bpf.h"

SEC("xdp")
int xdp_firewall(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_DROP;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_DROP;

    __u8 protocol = ip->protocol;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u16 dst_port = 0;

    __u32 key = 0;
    __u32 *local_ip = bpf_map_lookup_elem(&local_ip_map, &key);
    if (!local_ip) return XDP_DROP;

    int is_inbound = (bpf_ntohl(ip->daddr) == *local_ip);

    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) return XDP_DROP;
        dst_port = tcp->dest;
    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end) return XDP_DROP;
        dst_port = udp->dest;
    }

    if (is_traffic_allowed(pid, protocol, is_inbound ? src_ip : dst_ip, dst_port, is_inbound) == BLOCK) {
        return XDP_DROP;
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
