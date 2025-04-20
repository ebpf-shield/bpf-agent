// long is_same_comm = bpf_strncmp(key.comm, TASK_COMM_LEN, "curl");

// if (is_same_comm == 0)
// {
//     bpf_printk("Found %s\n", key.comm);

//     __u32 daddr = rule_array->rules[0].daddr;
//     if (daddr)
//     {
//         bpf_printk("Real daddr %d\n", bpf_ntohl(ctx->user_ip4));
//         bpf_printk("Found daddr %d\n", daddr);
//     }

//     __u16 dport = rule_array->rules[0].dport;

//     bpf_printk("Real dport %d\n", bpf_ntohs(ctx->user_port));
// }

// struct rule_val_s val = {};
// val.proto = ctx->protocol;
// // bpf_ntohl is for u32
// val.daddr = bpf_ntohl(ctx->user_ip4);
// // Short is for u16
// val.dport = bpf_ntohs(ctx->user_port);

// char ip_buf[INET_ADDRSTRLEN];

// Elf64_Addr data[4];
// data[0] = (val.daddr >> 24) & 0xFF;
// data[1] = (val.daddr >> 16) & 0xFF;
// data[2] = (val.daddr >> 8) & 0xFF;
// data[3] = val.daddr & 0xFF;

// bpf_snprintf(ip_buf, sizeof(ip_buf), "%d.%d.%d.%d", data, sizeof(data));

// bpf_printk("proto=%d daddr=%s dport=%d comm=%s\n", val.proto, ip_buf, val.dport, key.comm);