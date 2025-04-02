package rules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/google/gopacket/layers"
)

type RuleKey struct {
	SrcIP    uint32
	DstPort  uint16
	Protocol uint8
	Padding  uint8
}

type Rule struct {
	Saddr    string `json:"saddr"`
	Dport    uint16 `json:"dport"`
	Protocol string `json:"protocol"`
	Action   string `json:"action"`
	Chain    string `json:"chain"`
}

type RuleSet struct {
	Command string `json:"command"`
	Rules   []Rule `json:"rules"`
}

func SyncRules(getURL string, rulesMap *ebpf.Map) {
	resp, err := http.Get(getURL)
	if err != nil {
		log.Printf("GET failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	timestamp := time.Now().Format("20060102_150405")
	_ = os.WriteFile(filepath.Join("debug_agent_logs", "debug_received_"+timestamp+".json"), buf.Bytes(), 0644)

	var payload []RuleSet
	if err := json.Unmarshal(buf.Bytes(), &payload); err != nil {
		log.Printf("Failed to parse rules JSON: %v", err)
		return
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
	for _, entry := range payload {
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
