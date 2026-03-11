// Package registryutil provides shared utilities for registry URL normalization and matching.
package registryutil

import (
	"net/url"
	"strings"
)

// NormalizeRegistryHost extracts and normalizes the host portion of a registry
// URL or auth key for comparison. It strips scheme, path, and trailing slashes,
// and lowercases the result.
//
// Examples:
//
//	"https://quay.io/v1/"  → "quay.io"
//	"quay.io"              → "quay.io"
//	"//Docker.IO/"         → "docker.io"
//	"localhost:5000"       → "localhost:5000"
func NormalizeRegistryHost(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err == nil && parsed.Host != "" {
			value = parsed.Host
		}
	}
	value = strings.TrimPrefix(value, "//")
	value = strings.SplitN(value, "/", 2)[0]
	value = strings.TrimSuffix(value, "/")
	return strings.ToLower(strings.TrimSpace(value))
}

// RegistryHostMatches returns true if two registry references resolve to the
// same host after normalization. Returns false if either value is empty.
func RegistryHostMatches(a, b string) bool {
	hostA := NormalizeRegistryHost(a)
	hostB := NormalizeRegistryHost(b)
	if hostA == "" || hostB == "" {
		return false
	}
	return hostA == hostB
}
