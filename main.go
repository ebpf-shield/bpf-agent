package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	ebpfloader "github.com/ebpf-shield/bpf-agent/ebpf_loader"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Println("Starting BPF agent...")

	configs.InitEnv()
	httpClient := client.GetClient()
	defer httpClient.Close()

	registeredAgent, err := configs.InitAgent()

	if err != nil {
		log.Fatalf("creating agent id: %v", err)
	}

	exists, err := httpClient.Agent().ExistsById(registeredAgent.ID)
	if err != nil {
		log.Fatalf("checking agent existence: %v", err)
	}

	if !exists {
		err = httpClient.Agent().Create(client.CreateAgentDTO{
			Id:             registeredAgent.ID,
			OrganizationId: registeredAgent.OrganizationId,
		})
		if err != nil {
			log.Fatalf("creating agent: %v", err)
		}
	}

	objs, err := ebpfloader.LoadFirewallObjects()
	if err != nil {
		log.Fatalf("loading eBPF objects: %v", err)
	}
	defer objs.Close()

	cGroupPath := "/sys/fs/cgroup"
	link, err := link.AttachCgroup(link.CgroupOptions{
		Program: objs.LogConnect,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Path:    cGroupPath,
	})

	if err != nil {
		log.Fatalf("attaching program: %v", err)
	}
	defer link.Close()

	go processWorker(ctx)
	go ruleSyncWorker(ctx)

	<-ctx.Done()
	log.Println("shutting down gracefully, press Ctrl+C again to force")
}
