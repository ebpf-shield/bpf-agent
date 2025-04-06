package client

import (
	"log"

	"github.com/ebpf-shield/bpf-agent/configs"
	"resty.dev/v3"
)

func New() *resty.Client {
	client := resty.New()
	backendUrl, err := configs.GetEnv("BACKEND_URL")
	if err != nil {
		log.Fatalf("Failed to get BACKEND_URL: %v", err)
	}

	client.SetBaseURL(backendUrl)
	return client
}
