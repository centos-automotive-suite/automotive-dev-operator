package controllerutils

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TTLConfigProvider is implemented by OperatorConfig sections that provide
// a default build TTL (e.g. OSBuildsConfig, ContainerBuildsConfig).
// Implementations must be nil-safe: calling GetDefaultBuildTTL on a nil
// receiver returns DefaultBuildTTL ("24h").
type TTLConfigProvider interface {
	GetDefaultBuildTTL() string
}

// ResolveBuildTTL resolves the effective TTL for a build.
// Priority: specTTL (per-build) > configSection.GetDefaultBuildTTL() > "24h".
// Returns 0 if expiry is disabled (TTL string is "0").
func ResolveBuildTTL(specTTL string, configSection TTLConfigProvider) (time.Duration, error) {
	ttlStr := specTTL
	if ttlStr == "" {
		ttlStr = configSection.GetDefaultBuildTTL()
	}
	if ttlStr == "0" {
		return 0, nil
	}
	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return 0, err
	}
	if ttl < 0 {
		return 0, fmt.Errorf("TTL must not be negative: %s", ttlStr)
	}
	return ttl, nil
}

// ComputeExpiresAt computes the desired ExpiresAt value from a raw time,
// truncating to second precision. Reports whether the value differs from
// current and needs a status update.
func ComputeExpiresAt(current *metav1.Time, expiresAt *time.Time) (*metav1.Time, bool) {
	var desired *metav1.Time
	if expiresAt != nil {
		truncated := expiresAt.Truncate(time.Second)
		t := metav1.NewTime(truncated)
		desired = &t
	}
	if current == nil && desired == nil {
		return nil, false
	}
	if current != nil && desired != nil && current.Time.Equal(desired.Time) {
		return desired, false
	}
	return desired, true
}
