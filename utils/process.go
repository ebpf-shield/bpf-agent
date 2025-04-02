package utils

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"xdp-agent/config"
)

type ProcessInfo struct {
	Command string `json:"command"`
	PID     int    `json:"pid"`
}

func ListProcesses() []ProcessInfo {
	out, err := exec.Command("ps", "-eo", "pid,comm").Output()
	if err != nil {
		log.Printf("Failed to list processes: %v", err)
		return nil
	}
	lines := strings.Split(string(out), "\n")
	var processes []ProcessInfo
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			pid, _ := strconv.Atoi(fields[0])
			processes = append(processes, ProcessInfo{
				PID:     pid,
				Command: fields[1],
			})
		}
	}
	return processes
}

func SendProcessList(cfg config.Config, procs []ProcessInfo) {
	data, _ := json.MarshalIndent(procs, "", "  ")
	timestamp := time.Now().Format("20060102_150405")
	_ = os.WriteFile(filepath.Join("debug_agent_logs", "debug_sent_"+timestamp+".json"), data, 0644)

	resp, err := exec.Command("curl", "-X", "PATCH", cfg.PostURL, "-H", "Content-Type: application/json", "-d", string(data)).Output()
	if err != nil {
		log.Printf("Failed to PATCH process list: %v", err)
		return
	}
	log.Printf("✅ Sent process list (%d), response: %s", len(procs), string(resp))
}
