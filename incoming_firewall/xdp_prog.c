// xdp_prog.c  (Good Code 3 — Blacklist)
// XDP firewall in BLACKLIST mode that:
//   1) Checks if a process is listening on the packet’s dst port. (If none, PASS.)
//   2) Drops packets whose (src IP, dst port) appear in rules_map (action="drop").
//   3) Emits debug printk messages for PASS/DROP decisions.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>       // for IPPROTO_TCP, IPPROTO_UDP
#include <linux/tcp.h>
#include <linux/udp.h>

#define MAX_COMM 16  // Max length of process name stored in listener_map

// -----------------------------------------------------------------------------
// Data structures
// -----------------------------------------------------------------------------

// rule_key is the key for rules_map: source IP + destination port
struct rule_key {
    __u32 saddr;   // raw IPv4 address in network-byte order
    __u16 dport;   // destination port in host-byte order
    __u16 pad;     // padding to align struct to 8 bytes
};

// -----------------------------------------------------------------------------
// BPF maps
// -----------------------------------------------------------------------------

// listener_map: dst port → process command name (fixed-length string)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u16);            // port
    __type(value, char[MAX_COMM]); // process name
} listener_map SEC(".maps");

// rules_map: (src IP, dst port) → drop (value=0)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct rule_key); // composite key
    __type(value, __u8);          // 0 = drop
} rules_map SEC(".maps");

// -----------------------------------------------------------------------------
// Debugging helper
// -----------------------------------------------------------------------------

// PRINTK wraps bpf_trace_printk for simple debug output.
// Usage: PRINTK("msg %d\n", value);
#define PRINTK(fmt, ...) \
    bpf_trace_printk(fmt, sizeof(fmt), ##__VA_ARGS__)

// -----------------------------------------------------------------------------
// XDP program entry point
// -----------------------------------------------------------------------------

SEC("xdp")
int xdp_firewall(struct xdp_md *ctx) {
    // 1) Bounds check Ethernet header
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data     = (void *)(unsigned long)ctx->data;
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    // 2) Only handle IPv4 packets
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    // 3) Bounds check IP header
    struct iphdr *iph = data + sizeof(*eth);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    // 4) Extract source IP and protocol
    __u32 saddr = iph->saddr;
    __u8 proto  = iph->protocol;
    __u16 dport = 0;

    // 5) Parse TCP or UDP header to extract destination port
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (void*)iph + sizeof(*iph);
        if ((void*)(tcph + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(tcph->dest);

    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (void*)iph + sizeof(*iph);
        if ((void*)(udph + 1) > data_end)
            return XDP_PASS;
        dport = bpf_ntohs(udph->dest);

    } else {
        // Other protocols are not handled by this firewall logic
        return XDP_PASS;
    }

    // -------------------------------------------------------------------------
    // 1) If no process is listening on this dst port → PASS
    // -------------------------------------------------------------------------
    char *comm = bpf_map_lookup_elem(&listener_map, &dport);
    if (!comm) {
        PRINTK("PASS (no listener) saddr=0x%x dport=%d\n", saddr, dport);
        return XDP_PASS;
    }

    // -------------------------------------------------------------------------
    // 2) If (saddr, dport) appears in rules_map → DROP (blacklist)
    //    Otherwise → PASS
    // -------------------------------------------------------------------------
    struct rule_key key = {
        .saddr = saddr,
        .dport = dport,
        .pad   = 0,
    };

    __u8 *ruleVal = bpf_map_lookup_elem(&rules_map, &key);
    if (ruleVal && *ruleVal == 0) {
        // Blacklisted: drop
        PRINTK("DROP saddr=0x%x dport=%d comm=%s\n", saddr, dport, comm);
        return XDP_DROP;
    }

    // Not in blacklist: pass
    PRINTK("PASS (not listed) saddr=0x%x dport=%d comm=%s\n", saddr, dport, comm);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
