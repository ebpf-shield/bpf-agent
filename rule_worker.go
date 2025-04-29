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

func parseIP(ip string) uint32 {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(parsed)
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
					val.Rules[i].Daddr = parseIP(rule.Daddr)
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
