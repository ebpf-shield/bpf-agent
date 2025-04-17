package ebpfloader

import (
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func LoadAndAttachXDP(progName string, ifaceName string) (*ebpf.Map, *ebpf.Collection, link.Link) {
	spec, err := ebpf.LoadCollectionSpec("./xdp_firewall.o")
	if err != nil {
		log.Fatalf("Failed to load eBPF spec: %v", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("Failed to create collection: %v", err)
	}

	prog := coll.Programs[progName]
	if prog == nil {
		log.Fatalf("Program %s not found in eBPF object", progName)
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

	log.Printf("🛡️  XDP firewall attached to %s", ifaceName)

	rulesMap := coll.Maps["rules"]
	if rulesMap == nil {
		log.Fatalf("rules map not found")
	}

	return rulesMap, coll, lnk
}
