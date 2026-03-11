package registryutil

import "testing"

func TestRegistryHostMatches(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want bool
	}{
		{"same host", "quay.io", "quay.io", true},
		{"scheme stripped", "https://quay.io", "quay.io", true},
		{"path stripped", "https://quay.io/v1/", "quay.io", true},
		{"case insensitive", "Quay.IO", "quay.io", true},
		{"port preserved", "localhost:5000", "localhost:5000", true},
		{"different hosts", "quay.io", "docker.io", false},
		{"subdomain not matched", "quay.io", "quay.io.evil.com", false},
		{"different ports", "localhost:5000", "localhost:5001", false},
		{"empty rejected", "", "quay.io", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RegistryHostMatches(tt.a, tt.b); got != tt.want {
				t.Errorf("RegistryHostMatches(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
