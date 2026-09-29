package registryutil

import "testing"

func TestPinDigest(t *testing.T) {
	cases := []struct{ name, ref, digest, want string }{
		{"empty digest", "quay.io/org/img:tag", "", "quay.io/org/img:tag"},
		{"empty URL", "", "sha256:abc", ""},
		{"append digest", "quay.io/org/img:tag", "sha256:abc", "quay.io/org/img:tag@sha256:abc"},
		{"already pinned", "quay.io/org/img@sha256:abc", "sha256:def", "quay.io/org/img@sha256:abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PinDigest(tc.ref, tc.digest); got != tc.want {
				t.Fatalf("PinDigest() = %q, want %q", got, tc.want)
			}
		})
	}
}
