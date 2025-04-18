package client

import (
	"fmt"

	"github.com/ebpf-shield/bpf-agent/models"
	"go.mongodb.org/mongo-driver/v2/bson"
	"resty.dev/v3"
)

type agentService interface {
	Create(agentId bson.ObjectID) error
}

const agentPrefix = "/agent"

type agentServiceImpl struct {
	restyClient *resty.Client
}

func newAgentService(restyClient *resty.Client) agentService {
	return &agentServiceImpl{
		restyClient: restyClient,
	}
}

func (a *agentServiceImpl) Create(agentId bson.ObjectID) error {
	routeUrl := fmt.Sprint(agentPrefix)

	createAgent := models.CreateAgent{
		Id: agentId,
	}

	res, err := a.restyClient.R().SetBody(createAgent).Post(routeUrl)
	if err != nil {
		return err
	}

	if res.IsError() {
		return res.Err
	}

	return nil
}
