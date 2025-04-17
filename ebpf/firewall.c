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

static __always_inline char *ip_to_str(__u32 ip, char *buf, int buflen)
{
    if (!buf || buflen < 16)
        return NULL;

    __u8 bytes[4];
    bytes[0] = (ip >> 24) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[3] = ip & 0xFF;

    // We need to match how bpf_snprintf expects arguments:
    // - format string
    // - array of 64-bit values (Elf64_Addr*) for the format args

    Elf64_Addr data[4];
    data[0] = bytes[0];
    data[1] = bytes[1];
    data[2] = bytes[2];
    data[3] = bytes[3];

    const char fmt[] = "%d.%d.%d.%d";

    bpf_snprintf(buf, buflen, fmt, data, 4);

    return buf;
}

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
