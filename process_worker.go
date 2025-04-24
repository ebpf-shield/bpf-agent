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

func listProcesses(processesToExclude []string) []models.Process {
	command := "ps -eo comm | tail -n +2 | sort | uniq -c | sort -nr"
	out, err := exec.Command("bash", "-c", command).Output()
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
			exclude := false

			count, _ := strconv.Atoi(fields[0])
			comm := fields[1]

			if strings.Contains(comm, "ps") {
				continue
			}

			for _, excludeProcess := range processesToExclude {
				if strings.Contains(comm, excludeProcess) {
					exclude = true
					break
				}
			}

			if exclude {
				continue
			}

			processes = append(processes, models.Process{
				Count:   count,
				Command: comm,
			})
		}
	}

	return processes
}

func processWorker(ctx context.Context) {
	httpClient := client.GetClient()
	id := configs.GetAgentUUID()

	tick := time.Tick(time.Second * 5)
	for {
		select {
		case <-ctx.Done():
			return

		case <-tick:
			processesToExclude, err := httpClient.Agent().GetProcessesToExcludeById(id)
			if err != nil {
				log.Printf("Failed to get processes to exclude: %v", err)
			}

			processess := listProcesses(processesToExclude)

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
