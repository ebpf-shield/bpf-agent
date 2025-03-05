#ifndef FIREWALL_STRUCTS_H
#define FIREWALL_STRUCTS_H

#define BLOCK 0
#define ALLOW 1
#define MAX_RULES 10  // Maximum number of firewall rules per process

// 🔹 Firewall Rule Structure (Each rule includes all conditions together)
struct firewall_rule {
    __u8 protocol;      // Protocol (TCP=6, UDP=17)
    __u32 ip;           // Source IP (for inbound) or Destination IP (for outbound)
    __u16 port_start;   // Port range start
    __u16 port_end;     // Port range end
};

// 🔹 Per-Process Firewall Rule Set (Each process has multiple rules)
struct process_firewall {
    __u8 allow_all;  // If set to 1, all traffic is allowed for this process
    struct firewall_rule inbound_rules[MAX_RULES];  // Rules for incoming traffic
    struct firewall_rule outbound_rules[MAX_RULES]; // Rules for outgoing traffic
};

// 🔹 eBPF Map: Stores firewall rules per **PID**
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);  // Process ID (PID)
    __type(value, struct process_firewall);
} process_firewall SEC(".maps");

// 🔹 eBPF Map: Stores the local server IP address dynamically
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);  // Only one entry needed for LOCAL_IP
    __type(key, __u32);
    __type(value, __u32);
} local_ip_map SEC(".maps");

#endif // FIREWALL_STRUCTS_H
