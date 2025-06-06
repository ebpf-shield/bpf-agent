package configs

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const EbShieldDir = "/var/lib/ebshield/"
const AgentIDPath = EbShieldDir + "agent_id"
const OrganizationIdPath = EbShieldDir + "org_id"

const OrganizatioEnvName = "AGENT_ORG_ID"

type RegisteredAgent struct {
	ID             bson.ObjectID
	OrganizationId bson.ObjectID
}

var (
	registeredAgent RegisteredAgent
	initAgentOnce   sync.Once
)

func setAgentID(dir string) (bson.ObjectID, error) {
	var id bson.ObjectID

	f, err := os.OpenFile(AgentIDPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, // fail if exists
		0o600,                             // user-read/write only
	)

	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Already created by a previous run → just read it
			data, err := os.ReadFile(AgentIDPath)
			if err != nil {
				return id, fmt.Errorf("read existing agent id: %w", err)
			}
			// We return an error to indicate that the AGENT ID already exists
			// The caller checks for this error and not crash the program
			hex := strings.TrimSpace(string(data))
			id, err := bson.ObjectIDFromHex(hex)

			if err != nil {
				return id, fmt.Errorf("invalid agent id format: %s", hex)
			}

			return id, nil
		}

		return id, fmt.Errorf("create agent id file: %w", err)
	}

	defer f.Close()

	id = bson.NewObjectID()
	if _, err := f.WriteString(id.Hex()); err != nil {
		return id, fmt.Errorf("write agent id: %w", err)
	}

	if err := os.Chmod(AgentIDPath, 0o400); err != nil {
		return id, fmt.Errorf("chmod read-only: %w", err)
	}

	return id, nil
}

func setOrganizationID(dir string) (bson.ObjectID, error) {
	var id bson.ObjectID

	f, err := os.OpenFile(OrganizationIdPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, // fail if exists
		0o600,                             // user-read/write only
	)

	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Already created by a previous run → just read it
			data, err := os.ReadFile(OrganizationIdPath)
			if err != nil {
				return id, fmt.Errorf("read existing organization id: %w", err)
			}

			// We return an error to indicate that the ORGANIZATION ID already exists
			// The caller checks for this error and not crash the program
			hex := strings.TrimSpace(string(data))
			id, err := bson.ObjectIDFromHex(hex)
			if err != nil {
				return id, fmt.Errorf("invalid organization id format: %s", hex)
			}

			return id, nil
		}

		return id, fmt.Errorf("create organization id file: %w", err)
	}

	defer f.Close()

	orgIdStr := os.Getenv(OrganizatioEnvName)

	if orgIdStr == "" {
		return id, fmt.Errorf("environment variable %s is not set", OrganizatioEnvName)
	}
	id, err = bson.ObjectIDFromHex(orgIdStr)

	if err != nil {
		return id, fmt.Errorf("invalid organization id format: %s", orgIdStr)
	}

	if _, err := f.WriteString(id.Hex()); err != nil {
		return id, fmt.Errorf("write organization id: %w", err)
	}

	if err := os.Chmod(OrganizationIdPath, 0o400); err != nil {
		return id, fmt.Errorf("chmod read-only: %w", err)
	}

	return id, nil
}

// getAgentID returns the existing agent id in agent id Path, or automically
// creates it (with a newly-generated agent id) on first run.
func newRegisteredAgent() (RegisteredAgent, error) {
	dir := filepath.Dir(EbShieldDir)
	// 1) Ensure the parent directory exists (owner: root, perms: 755)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return registeredAgent, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	agentId, err := setAgentID(dir)
	if err != nil {
		return registeredAgent, fmt.Errorf("set agent id: %w", err)
	}

	if agentId.IsZero() {
		return registeredAgent, fmt.Errorf("agent id is zero, cannot proceed")
	}

	registeredAgent.ID = agentId

	orgId, err := setOrganizationID(dir)
	if err != nil {
		return registeredAgent, fmt.Errorf("set organization id: %w", err)
	}

	if orgId.IsZero() {
		return registeredAgent, fmt.Errorf("organization id is zero, cannot proceed")
	}

	registeredAgent.OrganizationId = orgId

	return registeredAgent, nil
}

func GetRegisteredAgent() RegisteredAgent {
	if registeredAgent.ID.IsZero() {
		log.Fatalln("Agent ID not initialized. Call InitAgentID() first.")
	}

	if registeredAgent.OrganizationId.IsZero() {
		log.Fatalln("Organization ID not initialized. Call InitAgentID() first.")
	}

	return registeredAgent
}

func InitAgent() (RegisteredAgent, error) {
	var mainErr error

	initAgentOnce.Do(func() {
		agent, err := newRegisteredAgent()

		mainErr = err
		registeredAgent = agent
	})

	return registeredAgent, mainErr
}
