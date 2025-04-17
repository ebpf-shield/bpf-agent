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
    __u32 daddr;
    __u16 dport;
    __u8 action;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct cmd_key_s);
    __type(value, struct rule_val_s);
} firewall_rules SEC(".maps");

SEC("cgroup/connect4")
int log_connect(struct bpf_sock_addr *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    struct cmd_key_s key = {};
    __builtin_memcpy(key.comm, comm, sizeof(comm));

    struct rule_val_s val = {};
    val.proto = ctx->protocol;
    // bpf_ntohl is for u32
    val.daddr = bpf_ntohl(ctx->user_ip4);
    // Short is for u16
    val.dport = bpf_ntohs(ctx->user_port);

    char ip_buf[INET_ADDRSTRLEN];
    ip_to_str(val.daddr, ip_buf, INET_ADDRSTRLEN);
    bpf_printk("ip=%s", ip_buf);

    bpf_printk("proto=%d daddr=%s dport=%d comm=\n", val.proto, ip_buf, val.dport, key.comm);

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
