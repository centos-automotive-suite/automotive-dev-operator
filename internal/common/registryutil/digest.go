package registryutil

import "strings"

// PinDigest appends @digest unless the reference is already pinned.
func PinDigest(registryURL, digest string) string {
	if registryURL == "" || digest == "" {
		return registryURL
	}
	if strings.Contains(registryURL, "@") {
		return registryURL
	}
	return registryURL + "@" + digest
}
