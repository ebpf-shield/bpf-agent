package main

import (
	"context"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/ebpf-shield/bpf-agent/client"
	"github.com/ebpf-shield/bpf-agent/configs"
	"github.com/ebpf-shield/bpf-agent/models"
)

func listProcesses() []models.Process {
	out, err := exec.Command("ps", "-eo", "pid,comm").Output()
	if err != nil {
		log.Printf("Failed to list processes: %v", err)
		return nil
	}

	lines := strings.Split(string(out), "\n")

	var processes []models.Process
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}

		fields := strings.Fields(line)

		if len(fields) >= 2 {
			pid, _ := strconv.Atoi(fields[0])
			comm := fields[1]

			if strings.Contains(comm, "ps") {
				continue
			}

			if strings.Contains(comm, "kworker") {
				continue
			}

			processes = append(processes, models.Process{
				PID:     pid,
				Command: comm,
			})
		}
	}

	return processes
}

func processWorker(ctx context.Context) {
	var err error
	httpClient := client.GetClient()

	tick := time.Tick(time.Second * 5)
	for {
		select {
		case <-ctx.Done():
			return

		case <-tick:
			processess := listProcesses()
			id := configs.GetAgentUUID()

			err = httpClient.Process().ReplaceProcesses(processess, id)
			if err != nil {
				log.Printf("Failed to send process list: %v", err)
				// TODO: return the error with errgroup
				continue
			}

			log.Printf("Sent process list to server")
		}
	}
}
