package configs

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ebpf-shield/bpf-agent/errors/apperrors"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const UUIDPath = "/var/lib/ebshield/uuid"

var (
	agentId         bson.ObjectID
	initAgentIdOnce sync.Once
)

// getAgentUUID returns the existing UUID in uuidPath, or atomically
// creates it (with a newly-generated uuid) on first run.
func newAgentUUID() (bson.ObjectID, error) {
	dir := filepath.Dir(UUIDPath)
	// 1) Ensure the parent directory exists (owner: root, perms: 755)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return agentId, fmt.Errorf("mkdir %s: %w", dir, err)
	}

	// 2) Try to create the file exclusively
	f, err := os.OpenFile(UUIDPath,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY, // fail if exists
		0o600,                             // user-read/write only
	)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Already created by a previous run → just read it
			data, err := os.ReadFile(UUIDPath)
			if err != nil {
				return agentId, fmt.Errorf("read existing uuid: %w", err)
			}
			// We return an error to indicate that the UUID already exists
			// The caller checks for this error and not crash the program
			hex := strings.TrimSpace(string(data))
			id, err := bson.ObjectIDFromHex(hex)

			if err != nil {
				return agentId, fmt.Errorf("invalid uuid format: %s", hex)
			}

			agentId = id
			return agentId, apperrors.ErrUUIDExists
		}

		return agentId, fmt.Errorf("create uuid file: %w", err)
	}

	defer f.Close()

	newID := bson.NewObjectID()
	if _, err := f.WriteString(newID.Hex()); err != nil {
		return agentId, fmt.Errorf("write uuid: %w", err)
	}

	if err := os.Chmod(UUIDPath, 0o400); err != nil {
		return agentId, fmt.Errorf("chmod read-only: %w", err)
	}

	return newID, nil
}

func GetAgentUUID() bson.ObjectID {
	if agentId.IsZero() {
		log.Fatalln("Agent UUID not initialized. Call InitAgentUUID() first.")
	}

	return agentId
}

func InitAgentUUID() (bson.ObjectID, error) {
	var mainErr error

	initAgentIdOnce.Do(func() {
		uuid, err := newAgentUUID()

		mainErr = err
		agentId = uuid
	})

	return agentId, mainErr
}
