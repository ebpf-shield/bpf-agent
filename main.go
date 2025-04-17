package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	link, err := link.AttachCgroup(link.CgroupOptions{
		Program: objs.firewallPrograms.LogConnect,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Path:    "/sys/fs/cgroup",
	})

	if err != nil {
		log.Fatalf("attaching program: %v", err)
	}
	defer link.Close()

	<-ctx.Done()
	fmt.Println()
	log.Println("shutting down gracefully, press Ctrl+C again to force")
}
