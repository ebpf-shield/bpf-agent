package main

import (
	"bytes"
	"context"
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
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	"github.com/ebpf-shield/bpf-agent/models"
	"github.com/ebpf-shield/bpf-agent/rules"
	"github.com/ebpf-shield/bpf-agent/utils"
)

func ipToStr(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Usage: xdp_firewall <interface>")
	}

	ifaceName := os.Args[1]

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", ifaceName, err)
	}

	configs.InitEnv()
	httpClient := client.GetClient()

	spec, err := ebpf.LoadCollectionSpec("xdp_firewall.o")
	if err != nil {
		log.Fatalf("Failed to load BPF spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["xdp_firewall_prog"]
	if prog == nil {
		log.Fatalf("Missing program: xdp_firewall_prog")
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		for {
			processess := utils.ListProcesses()
			id := bson.NewObjectID()
			err := httpClient.Process.ReplaceProcesses(processess, id)
			if err != nil {
				log.Printf("Failed to send process list: %v", err)
				continue
			}

			rules.SyncRules(rulesMap)
			time.Sleep(30 * time.Second)
		}
	}()

	log.Println("Listening for events...")

	go func() {
		for {
			record, err := reader.Read()
			if err != nil {
				log.Printf("Perf read error: %v", err)
				continue
			}
			var event models.Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("Failed to decode event: %v", err)
				continue
			}
			action := "❌ BLOCKED"
			if event.Allowed == 1 {
				action = "✅ ALLOWED"
			}
			log.Printf("[IN] %s:%d -> %s", ipToStr(event.SrcIP), event.DestPort, action)
		}
	}()

	<-ctx.Done()
	log.Println("🛑 Agent stopped")
}
