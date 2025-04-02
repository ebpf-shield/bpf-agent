package config

import (
	"encoding/json"
	"log"
	"os"
)

type Config struct {
	AgentID string `json:"agentId"`
	PostURL string `json:"postUrl"`
	GetURL  string `json:"getUrl"`
}

func Load() Config {
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("Failed to read config.json: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Invalid config.json: %v", err)
	}
	return cfg
}
