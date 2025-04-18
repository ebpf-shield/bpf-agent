// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netinet_in.h"
// #include <netinet/in.h>

struct cmd_key_s
{
    char comm[TASK_COMM_LEN];
};
struct rule_val_s
{
    __u8 proto;
    // The address has to be kept in network byte order
    __u32 daddr;
    __u16 dport;
    __u8 action;
};

struct rule_array_s
{
    struct rule_val_s rules[1024];
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct cmd_key_s);
    __type(value, struct rule_array_s);
    // __array(value, struct rule_val_s);
} firewall_rules SEC(".maps");

SEC("cgroup/connect4")
int log_connect(struct bpf_sock_addr *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    struct cmd_key_s key = {};
    __builtin_memcpy(key.comm, comm, sizeof(comm));

    // look up by key
    struct rule_array_s *rule_array = bpf_map_lookup_elem(&firewall_rules, &key);
    if (!rule_array)
    {
        bpf_printk("No firewall rules found for command: %s\n", comm);
        return 0;
    }

    struct rule_val_s val = {};
    val.proto = ctx->protocol;
    // bpf_ntohl is for u32
    val.daddr = bpf_ntohl(ctx->user_ip4);
    // Short is for u16
    val.dport = bpf_ntohs(ctx->user_port);

    char ip_buf[INET_ADDRSTRLEN];

    Elf64_Addr data[4];
    data[0] = (val.daddr >> 24) & 0xFF;
    data[1] = (val.daddr >> 16) & 0xFF;
    data[2] = (val.daddr >> 8) & 0xFF;
    data[3] = val.daddr & 0xFF;

    bpf_snprintf(ip_buf, sizeof(ip_buf), "%d.%d.%d.%d", data, sizeof(data));

    bpf_printk("proto=%d daddr=%s dport=%d comm=%s\n", val.proto, ip_buf, val.dport, key.comm);

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
