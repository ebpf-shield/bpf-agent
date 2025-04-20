#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "netinet_in.h"

#define RULE_FIREWALL_ALLOW 1
#define RULE_FIREWALL_DENY 0

#define CONNECT_ALLOW 1
#define CONNECT_DENY 0
#define MAX_RULES_PER_COMMAND 1024

struct iter_ctx
{
    struct bpf_sock_addr *sk; /* original ctx               */
    struct rule_val_s *rules; /* pointer into the rule set  */
    int verdict;              /* 1 = allow, 0 = block       */
};

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
    struct rule_val_s rules[MAX_RULES_PER_COMMAND];
};