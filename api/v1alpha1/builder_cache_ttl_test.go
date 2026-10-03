package v1alpha1

import (
	"testing"
	"time"
)

func TestGetBuilderCacheTTL(t *testing.T) {
	for _, tc := range []struct {
		name      string
		config    *OSBuildsConfig
		want      time.Duration
		wantError bool
	}{
		{"nil", nil, 30 * 24 * time.Hour, false},
		{"default", &OSBuildsConfig{}, 30 * 24 * time.Hour, false},
		{"disabled", &OSBuildsConfig{BuilderCacheTTL: "0"}, 0, false},
		{"custom", &OSBuildsConfig{BuilderCacheTTL: "168h"}, 7 * 24 * time.Hour, false},
		{"negative", &OSBuildsConfig{BuilderCacheTTL: "-1h"}, 0, true},
		{"invalid", &OSBuildsConfig{BuilderCacheTTL: "30 days"}, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.config.GetBuilderCacheTTL()
			if got != tc.want || (err != nil) != tc.wantError {
				t.Fatalf("got %s, %v; want %s, error=%v", got, err, tc.want, tc.wantError)
			}
		})
	}
}
