package controllerutils

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type stubTTLConfig struct {
	ttl string
}

func (s *stubTTLConfig) GetDefaultBuildTTL() string {
	if s != nil && s.ttl != "" {
		return s.ttl
	}
	return "24h"
}

func TestResolveBuildTTL(t *testing.T) {
	cases := []struct {
		name        string
		specTTL     string
		config      *stubTTLConfig
		expectedTTL time.Duration
		wantErr     bool
	}{
		{"spec overrides config", "48h", &stubTTLConfig{ttl: "72h"}, 48 * time.Hour, false},
		{"config default used when spec empty", "", &stubTTLConfig{ttl: "72h"}, 72 * time.Hour, false},
		{"nil config falls back to 24h", "", (*stubTTLConfig)(nil), 24 * time.Hour, false},
		{"zero disables expiry", "0", nil, 0, false},
		{"spec zero overrides config", "0", &stubTTLConfig{ttl: "72h"}, 0, false},
		{"negative TTL is error", "-1h", nil, 0, true},
		{"invalid TTL string is error", "bogus", nil, 0, true},
		{"minutes work", "30m", nil, 30 * time.Minute, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var config *stubTTLConfig
			if tc.config != nil {
				config = tc.config
			} else if tc.specTTL == "0" || tc.wantErr {
				config = &stubTTLConfig{}
			}

			ttl, err := ResolveBuildTTL(tc.specTTL, config)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ttl != tc.expectedTTL {
				t.Errorf("expected %v, got %v", tc.expectedTTL, ttl)
			}
		})
	}
}

func TestResolveBuildTTL_NilConfigSection(t *testing.T) {
	ttl, err := ResolveBuildTTL("", (*stubTTLConfig)(nil))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ttl != 24*time.Hour {
		t.Errorf("expected 24h fallback, got %v", ttl)
	}
}

func TestComputeExpiresAt(t *testing.T) {
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	nowMeta := metav1.NewTime(now)
	later := now.Add(24 * time.Hour)
	laterMeta := metav1.NewTime(later)

	cases := []struct {
		name       string
		current    *metav1.Time
		expiresAt  *time.Time
		wantUpdate bool
		wantNil    bool
	}{
		{"both nil", nil, nil, false, true},
		{"current nil, desired set", nil, &later, true, false},
		{"current set, desired nil", &nowMeta, nil, true, true},
		{"same time no update", &laterMeta, &later, false, false},
		{"different time needs update", &nowMeta, &later, true, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desired, needsUpdate := ComputeExpiresAt(tc.current, tc.expiresAt)
			if needsUpdate != tc.wantUpdate {
				t.Errorf("needsUpdate = %v, want %v", needsUpdate, tc.wantUpdate)
			}
			if tc.wantNil && desired != nil {
				t.Errorf("expected nil desired, got %v", desired)
			}
			if !tc.wantNil && desired == nil {
				t.Error("expected non-nil desired, got nil")
			}
		})
	}
}

func TestComputeExpiresAt_TruncatesToSeconds(t *testing.T) {
	withNanos := time.Date(2025, 6, 1, 12, 30, 45, 123456789, time.UTC)
	expected := time.Date(2025, 6, 1, 12, 30, 45, 0, time.UTC)

	desired, needsUpdate := ComputeExpiresAt(nil, &withNanos)
	if !needsUpdate {
		t.Fatal("expected update needed")
	}
	if !desired.Time.Equal(expected) {
		t.Errorf("expected %v, got %v", expected, desired.Time)
	}
}
