// go:build ignore

#include "firewall.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct cmd_key_s);
    __type(value, struct rule_array_s);
} firewall_rules SEC(".maps");

static long callback_fn(__u32 index, void *_ctx)
{
    bpf_printk("index = %d\n", index);
    struct iter_ctx *ctx = (struct iter_ctx *)_ctx;

    if (index >= MAX_RULES_PER_COMMAND)
    {
        bpf_printk("index out of bounds\n");
        return 0;
    }

    struct rule_val_s *rule = &ctx->rules[index];
    if (!rule)
    {
        return 0;
    }

    if (ctx->sk->user_ip4 && ctx->sk->user_port)
    {
        struct rule_val_s val = {};
        val.proto = ctx->sk->protocol;

        // ntoh is network byte order to host byte order
        // bpf_ntohl is for u32
        val.daddr = bpf_ntohl(ctx->sk->user_ip4);
        // Short is for u16
        val.dport = bpf_ntohs(ctx->sk->user_port);

        // Logs
        // bpf_printk("Found rule %d %d %d\n", rule->proto, rule->daddr, rule->dport);
        // bpf_printk("val.daddr = %d\n", val.daddr);
        // bpf_printk("val.dport = %d\n", val.dport);

        if (rule->daddr == val.daddr &&
            (rule->dport == 0 || rule->dport == val.dport))
        {
            /* decide verdict based on action */
            if (rule->action == RULE_FIREWALL_ALLOW)
            {
                ctx->verdict = CONNECT_ALLOW;
            }
            else
            {
                bpf_printk("Denying connection\n");
                ctx->verdict = CONNECT_DENY;
            }
            return 1;
        }
    }

    return 0;
}

SEC("cgroup/connect4")
// TODO: Rename the function
int log_connect(struct bpf_sock_addr *ctx)
{
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    struct cmd_key_s key = {};
    __builtin_memcpy(key.comm, comm, sizeof(comm));

    // look up by key
    struct rule_array_s *rule_array = (struct rule_array_s *)bpf_map_lookup_elem(&firewall_rules, &key);

    if (!rule_array)
    {
        bpf_printk("No rules for %s\n", key.comm);
        return 1;
    }

    struct iter_ctx i_ctx = {
        .sk = ctx,
        .rules = rule_array->rules,
        .verdict = CONNECT_ALLOW,
    };

    long (*cb_p)(__u32, void *) = &callback_fn;

    bpf_loop(MAX_RULES_PER_COMMAND, cb_p, &i_ctx, 0);

    bpf_printk("i_ctx.verdict = %d\n", i_ctx.verdict);
    return i_ctx.verdict;
}

char LICENSE[] SEC("license") = "GPL";
