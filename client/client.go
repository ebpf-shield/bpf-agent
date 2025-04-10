package client

import (
	"fmt"
	"log"
	"sync"

	"github.com/ebpf-shield/bpf-agent/configs"
	"resty.dev/v3"
)

var (
	initRestyClient sync.Once
	client          *clientImpl
)

type clientImpl struct {
	restyClient *resty.Client
	Process     processService
}

func GetClient() *clientImpl {
	initRestyClient.Do(func() {
		client = newClient()
	})

	return client
}

func newClient() *clientImpl {
	client := resty.New()
	backendUrl, err := configs.GetEnv("BACKEND_URL")
	if err != nil {
		log.Fatalf("Failed to get BACKEND_URL: %v", err)
	}

	baseUrl := fmt.Sprintf("%s/api/host", backendUrl)
	client.SetBaseURL(baseUrl)

	processService := newProcessService(client)

	return &clientImpl{
		restyClient: client,
		Process:     processService,
	}
}
