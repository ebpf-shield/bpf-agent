package ebpfloader

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/ebpf-shield/bpf-agent/models"
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

func SetRuleToFirewallRuleArrayEntry(rule models.Rule, val *firewallRuleArrayS, index int32) {
	staddr, edaddr, err := cidrRange(rule.Daddr)
	if err != nil {
		log.Printf("Failed to parse CIDR %s: %v", rule.Daddr, err)
		return
	}

	val.Rules[index].StartDaddr = staddr
	val.Rules[index].EndDaddr = edaddr
	val.Rules[index].Dport = rule.Dport
	val.Rules[index].Proto = parseProtocol(rule.Protocol)
	val.Rules[index].Action = parseAction(rule.Action)
}
