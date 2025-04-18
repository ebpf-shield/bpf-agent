package rules

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/google/gopacket/layers"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type RuleKey struct {
	SrcIP    uint32
	DstPort  uint16
	Protocol uint8
	Padding  uint8
}

func SyncRules(rulesMap *ebpf.Map) error {
	ruleSet, err := client.GetClient().Process().FindByAgentIdWithRulesByCommand(bson.NewObjectID())
	if err != nil {
		return err
	}

	// Clear old rules
	it := rulesMap.Iterate()
	var key RuleKey
	var val uint8
	for it.Next(&key, &val) {
		if err := rulesMap.Delete(key); err != nil {
			log.Printf("❌ Failed to delete rule: %+v", key)
		}
	}

	// Add new rules
	for _, entry := range ruleSet {
		for _, rule := range entry.Rules {
			if rule.Chain != "INPUT" || rule.Action != "ACCEPT" {
				continue
			}
			ip := parseIP(rule.Saddr)
			proto := parseProtocol(rule.Protocol)
			if ip == 0 || proto == 0 {
				continue
			}
			key := RuleKey{SrcIP: ip, DstPort: rule.Dport, Protocol: proto}
			val := uint8(1)
			if err := rulesMap.Put(key, val); err != nil {
				log.Printf("❌ Failed to insert rule for %s: %v", entry.Command, err)
			} else {
				log.Printf("✅ Rule added for %s: %s:%d %s", entry.Command, rule.Saddr, rule.Dport, rule.Protocol)
			}
		}
	}

	return nil
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

func parseIP(ip string) uint32 {
	parsed := net.ParseIP(ip).To4()
	if parsed == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(parsed)
}
