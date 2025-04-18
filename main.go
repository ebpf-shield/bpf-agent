package main

import (
	"context"
	"fmt"
	"log"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	"github.com/ebpf-shield/bpf-agent/errors/apperrors"
	"github.com/ebpf-shield/bpf-agent/utils"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configs.InitEnv()
	httpClient := client.GetClient()
	defer httpClient.Close()
	id, err := configs.InitAgentUUID()

	if err != nil {
		if err != apperrors.ErrUUIDExists {
			log.Fatalf("creating agent id: %v", err)
		}
		log.Printf("agent id already exists: %v", err)
	}
	// Register the agent.
	// We may need to register even if we generated the id.
	// At boot we need to ask the backend if he registered the agent with this id.
	err = httpClient.Agent().Create(id)
	if err != nil {
		log.Fatalf("creating agent: %v", err)
	}

	var objs firewallObjects
	if err := loadFirewallObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	cGroupPath := "/sys/fs/cgroup"
	link, err := link.AttachCgroup(link.CgroupOptions{
		Program: objs.firewallPrograms.LogConnect,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Path:    cGroupPath,
	})

	if err != nil {
		log.Fatalf("attaching program: %v", err)
	}
	defer link.Close()

	go func() {
		for {
			processess := utils.ListProcesses()
			id := configs.GetAgentUUID()
			if err != nil {
				log.Fatalf("Failed to get agent UUID: %v", err)
				continue
			}

			err = httpClient.Process().ReplaceProcesses(processess, id)
			if err != nil {
				log.Printf("Failed to send process list: %v", err)
				continue
			}

		}
	}()

	<-ctx.Done()
	fmt.Println()
	log.Println("shutting down gracefully, press Ctrl+C again to force")
}
