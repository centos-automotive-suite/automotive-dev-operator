package v1alpha1

import (
	"strings"
	"testing"
)

func TestValidateAIBLockfile(t *testing.T) {
	for _, tt := range []struct {
		name, content string
		valid         bool
	}{
		{"absent", "", true},
		{"v1 with entries", `{"version":1,"depsolves":{"abc":{"packages":[]}}}`, true},
		{"malformed", `{`, false},
		{"yaml", "version: 1", false},
		{"missing version", `{}`, false},
		{"null", `null`, false},
		{"array", `[]`, false},
		{"future version", `{"version":2}`, false},
		{"oversized", strings.Repeat(" ", MaxAIBLockfileSize) + `{"version":1}`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateAIBLockfile(tt.content); (err == nil) != tt.valid {
				t.Fatalf("error = %v, valid = %v", err, tt.valid)
			}
		})
	}
}
