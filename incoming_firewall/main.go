// main.go
// XDP-based per-(source IP, destination port) firewall in BLACKLIST mode.
// - Periodically syncs listening ports via netstat → listener_map
// - Periodically loads JSON rules (with an `action` field) → rules_map
// - Drops packets whose (src IP, dst port) have action="drop"; PASS otherwise

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	maxComm         = 16               // max length of process name in listener_map
	interfaceName   = "ens33"          // change to your network interface
	jsonRulesFile   = "rules.json"     // JSON file with blacklist rules
	refreshInterval = 10 * time.Second // map refresh period
)

// RuleEntry describes one firewall rule in the JSON file.
// Currently, only action="drop" is supported (blacklist).
type RuleEntry struct {
	Src    string `json:"src"`    // source IPv4 address, e.g. "192.168.1.5"
	Port   uint16 `json:"port"`   // destination port to match
	Action string `json:"action"` // "drop" (future: could add "log", "rate-limit", etc)
}

// ruleKey matches the key structure in the eBPF rules_map.
// Saddr is stored little-endian to match raw pkt.saddr.
type ruleKey struct {
	Saddr uint32
	Dport uint16
	Pad   uint16 // padding to align to 8 bytes
}

// clearMap deletes all entries from the given BPF map.
// keySize and valSize are the byte lengths of each map entry.
func clearMap(m *ebpf.Map, keySize, valSize int) error {
	keyBuf := make([]byte, keySize)
	valBuf := make([]byte, valSize)
	it := m.Iterate()
	for it.Next(&keyBuf, &valBuf) {
		if err := m.Delete(keyBuf); err != nil {
			return fmt.Errorf("deleting key %v: %w", keyBuf, err)
		}
	}
	return it.Err()
}

// runNetstatAndPopulate reads `netstat -tunlp` output,
// clears listener_map, and writes port→process name entries.
func runNetstatAndPopulate(m *ebpf.Map) error {
	out, err := exec.Command("netstat", "-tunlp").Output()
	if err != nil {
		return fmt.Errorf("running netstat: %w", err)
	}

	// Remove stale entries
	if err := clearMap(m, 2, maxComm); err != nil {
		log.Printf("warning clearing listener_map: %v", err)
	}

	// Parse each line of output
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}
		local, pidComm := fields[3], fields[6] // e.g. "0.0.0.0:22", "1234/sshd"
		parts := strings.SplitN(pidComm, "/", 2)
		if len(parts) != 2 {
			continue
		}
		comm := parts[1]
		idx := strings.LastIndex(local, ":")
		if idx < 0 {
			continue
		}
		var port uint16
		if _, err := fmt.Sscanf(local[idx+1:], "%d", &port); err != nil {
			continue
		}

		// Prepare fixed-size buffer for the command name
		var buf [maxComm]byte
		copy(buf[:], comm)

		// Insert into listener_map
		if err := m.Put(port, buf); err != nil {
			log.Printf("listener_map.Put(%d,%s): %v", port, comm, err)
		} else {
			log.Printf("listener_map[%d] = %s", port, comm)
		}
	}
	return nil
}

// loadRulesFromJSON reads rules.json, clears rules_map,
// and writes each (src IP, port) → drop (value=0) if action="drop".
// Future: extend to other actions.
func loadRulesFromJSON(m *ebpf.Map) error {
	data, err := os.ReadFile(jsonRulesFile)
	if err != nil {
		return fmt.Errorf("reading %s: %w", jsonRulesFile, err)
	}

	var entries []RuleEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing %s: %w", jsonRulesFile, err)
	}

	// Clear old rules (key = 8 bytes, val = 1 byte)
	if err := clearMap(m, 8, 1); err != nil {
		log.Printf("warning clearing rules_map: %v", err)
	}

	// Populate new rules
	for _, e := range entries {
		ip4 := net.ParseIP(e.Src).To4()
		if ip4 == nil {
			log.Printf("invalid src IP: %s", e.Src)
			continue
		}
		key := ruleKey{
			Saddr: binary.LittleEndian.Uint32(ip4),
			Dport: e.Port,
			Pad:   0,
		}

		// Only "drop" is supported in blacklist mode.
		if strings.ToLower(e.Action) != "drop" {
			// Skip any rule that is not "drop"
			log.Printf("skipping non-drop action '%s' for %s:%d", e.Action, e.Src, e.Port)
			continue
		}

		val := uint8(0) // 0 = drop
		if err := m.Put(key, val); err != nil {
			log.Printf("rules_map.Put(%+v,%d): %v", key, val, err)
		} else {
			log.Printf("rules_map[%s:%d] = drop", e.Src, e.Port)
		}
	}
	return nil
}

func main() {
	// --- 1) Compile the eBPF program ---
	clang := exec.Command("clang",
		"-g", "-O2", "-target", "bpf",
		"-c", "xdp_prog.c", "-o", "xdp_prog.o",
	)
	if out, err := clang.CombinedOutput(); err != nil {
		log.Fatalf("compiling xdp_prog.c: %v\n\n%s", err, out)
	}
	log.Println("Compiled xdp_prog.c")

	// --- 2) Load the compiled BPF collection ---
	spec, err := ebpf.LoadCollectionSpec("xdp_prog.o")
	if err != nil {
		log.Fatalf("loading spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("creating collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_firewall"]
	listenerMap := coll.Maps["listener_map"]
	rulesMap := coll.Maps["rules_map"]
	if prog == nil || listenerMap == nil || rulesMap == nil {
		log.Fatal("program or maps not found in collection")
	}

	// --- 3) Attach XDP program to interface ---
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		log.Fatalf("InterfaceByName(%s): %v", interfaceName, err)
	}
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("AttachXDP: %v", err)
	}
	defer lnk.Close()
	log.Printf("Attached XDP on %s (ifindex %d)", interfaceName, iface.Index)

	// --- 4) Start periodic map updaters ---
	listenerTicker := time.NewTicker(refreshInterval)
	rulesTicker := time.NewTicker(refreshInterval)
	quit := make(chan struct{})

	// Update listener_map every 10s
	go func() {
		runNetstatAndPopulate(listenerMap) // initial sync
		for {
			select {
			case <-listenerTicker.C:
				runNetstatAndPopulate(listenerMap)
			case <-quit:
				listenerTicker.Stop()
				return
			}
		}
	}()

	// Update rules_map every 10s
	go func() {
		loadRulesFromJSON(rulesMap) // initial load
		for {
			select {
			case <-rulesTicker.C:
				loadRulesFromJSON(rulesMap)
			case <-quit:
				rulesTicker.Stop()
				return
			}
		}
	}()

	// --- 5) Wait for shutdown signal ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	close(quit)

	log.Println("Detaching XDP and exiting")
}
