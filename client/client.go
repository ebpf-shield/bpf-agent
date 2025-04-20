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

// TODO: Does it really needs to be an interface
type Client interface {
	Close()
	Process() processService
	Agent() agentService
}

type clientImpl struct {
	restyClient *resty.Client
	process     processService
	agent       agentService
}

func (c *clientImpl) Close() {
	if c.restyClient != nil {
		c.restyClient.Close()
	}
}

func (c *clientImpl) Process() processService {
	return c.process
}

func (c *clientImpl) Agent() agentService {
	return c.agent
}

func GetClient() Client {
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
	agentService := newAgentService(client)

	return &clientImpl{
		restyClient: client,
		process:     processService,
		agent:       agentService,
	}
}
