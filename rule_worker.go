package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"time"

	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	ebpfloader "github.com/ebpf-shield/bpf-agent/ebpf_loader"
	"github.com/google/gopacket/layers"
)

func cidrRange(cidr string) (uint32, uint32, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0, err
	}

	// Start IP is simply the masked IP
	start := ip.Mask(ipnet.Mask)

	// End IP is calculated by setting all host bits to 1
	end := make(net.IP, len(start))
	copy(end, start)

	for i := range end {
		end[i] |= ^ipnet.Mask[i]
	}

	uint32Start := binary.BigEndian.Uint32(start)
	uint32End := binary.BigEndian.Uint32(end)

	return uint32Start, uint32End, nil
}

func parseProtocol(proto string) uint8 {
	switch proto {
	case "TCP":
		return uint8(layers.IPProtocolTCP)
	case "UDP":
		return uint8(layers.IPProtocolUDP)
	default:
		return 0
	}
}

func parseAction(action string) uint8 {
	switch action {
	case "ACCEPT":
		return 1
	case "DROP":
		return 0
	default:
		return 0
	}
}

func ruleSyncWorker(ctx context.Context) {
	httpClient := client.GetClient()
	firewallObjs := ebpfloader.GetFirewallObjects()
	tick := time.Tick(time.Second * 5)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
			id := configs.GetAgentUUID()
			data, err := httpClient.Process().FindByAgentIdWithRulesByCommand(id)
			if err != nil {
				log.Println("Failed to get rules by command:", err)
				// TODO: return the error with errgroup
				continue
			}

			for _, item := range data.RulesByCommand {
				if item.Command == "" {
					continue
				}

				if len(item.Rules) == 0 {
					continue
				}
				key := ebpfloader.NewFirewallCmdKeySFromComm(item.Command)
				val := ebpfloader.NewEmptyFirewallRuleArrayS()

				for i := range len(val.Rules) {
					if i >= len(item.Rules) {
						break
					}

					rule := item.Rules[i]
					staddr, edaddr, err := cidrRange(rule.Daddr)
					if err != nil {
						log.Printf("Failed to parse CIDR %s: %v", rule.Daddr, err)
						continue
					}

					val.Rules[i].StartDaddr = staddr
					val.Rules[i].EndDaddr = edaddr
					val.Rules[i].Dport = rule.Dport
					val.Rules[i].Proto = parseProtocol(rule.Protocol)
					val.Rules[i].Action = parseAction(rule.Action)
				}

				firewallObjs.FirewallRules.Put(key, val)
				log.Printf("Command %s have %d rules:", item.Command, len(item.Rules))

			}
		}
	}
}
