package v1alpha1

import (
	"encoding/json"
	"fmt"
)

const MaxAIBLockfileSize = 900 * 1024

// ValidateAIBLockfile checks the envelope; AIB validates individual locked requests.
func ValidateAIBLockfile(content string) error {
	if content == "" {
		return nil
	}
	if len(content) > MaxAIBLockfileSize {
		return fmt.Errorf("lockfile exceeds %d byte limit", MaxAIBLockfileSize)
	}
	var envelope struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal([]byte(content), &envelope); err != nil {
		return fmt.Errorf("lockfile must be an AIB JSON object with version 1")
	}
	if envelope.Version != 1 {
		return fmt.Errorf("unsupported AIB lockfile version %d: expected 1", envelope.Version)
	}
	return nil
}
