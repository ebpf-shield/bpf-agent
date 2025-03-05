#ifndef FIREWALL_HELPERS_H
#define FIREWALL_HELPERS_H

#include "firewall_structs.bpf.h"

// 🔹 Function: Check if a packet matches a firewall rule
static __always_inline int matches_rule(struct firewall_rule *rule, __u8 protocol, __u32 ip, __u16 port) {
    return (rule->protocol == protocol &&
            rule->ip == ip &&
            port >= rule->port_start &&
            port <= rule->port_end);
}

// 🔹 Function: Check if a packet is allowed based on all conditions
static __always_inline int is_traffic_allowed(__u32 pid, __u8 protocol, __u32 ip, __u16 port, int is_inbound) {
    struct process_firewall *rules = bpf_map_lookup_elem(&process_firewall, &pid);
    if (!rules) return BLOCK;  // No rules for this process? Block the packet.

    // 🔹 If "Allow All" is set, allow all traffic for this process
    if (rules->allow_all) return ALLOW;

    struct firewall_rule *rule_list = is_inbound ? rules->inbound_rules : rules->outbound_rules;

    // 🔹 Iterate over all firewall rules to check if one fully matches
    for (int i = 0; i < MAX_RULES; i++) {
        if (matches_rule(&rule_list[i], protocol, ip, port)) {
            return ALLOW; // ✅ If a rule fully matches, allow the packet
        }
    }
    return BLOCK; // ❌ No matching rule found, block the packet
}

// 🔹 Function: Remove firewall rules when a process exits
static __always_inline void remove_process_rules(__u32 pid) {
    bpf_map_delete_elem(&process_firewall, &pid);
}

#endif // FIREWALL_HELPERS_H
