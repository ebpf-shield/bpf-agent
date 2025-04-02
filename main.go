package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"xdp-agent/config"
	"xdp-agent/rules"
	"xdp-agent/utils"
)

type Event struct {
	SrcIP    uint32
	DestPort uint16
	Proto    uint8
	Allowed  uint8
}

func ipToStr(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <interface>", os.Args[0])
	}
	ifaceName := os.Args[1]
	cfg := config.Load()

	spec, err := ebpf.LoadCollectionSpec("xdp_firewall.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}

	prog := coll.Programs["xdp_firewall_prog"]
	if prog == nil {
		log.Fatalf("Missing program: xdp_firewall_prog")
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP: %v", err)
	}
	defer lnk.Close()

	log.Printf("🛡️  XDP firewall attached to %s", ifaceName)

	events := coll.Maps["events"]
	if events == nil {
		log.Fatalf("Missing 'events' map")
	}

	rulesMap := coll.Maps["rules"]
	if rulesMap == nil {
		log.Fatalf("Missing 'rules' map")
	}

	reader, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Failed to open perf buffer: %v", err)
	}
	defer reader.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			procs := utils.ListProcesses()
			utils.SendProcessList(cfg, procs)
			rules.SyncRules(cfg.GetURL, rulesMap)
			time.Sleep(30 * time.Second)
		}
	}()

	log.Println("📡 Listening for events...")

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Perf read error: %v", err)
				continue
			}
			var ev Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}
			action := "❌ BLOCKED"
			if ev.Allowed == 1 {
				action = "✅ ALLOWED"
			}
			log.Printf("[IN] %s:%d -> %s", ipToStr(ev.SrcIP), ev.DestPort, action)
		}
	}()

	<-stop
	log.Println("🛑 Agent stopped")
}
