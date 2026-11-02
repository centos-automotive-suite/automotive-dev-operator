package workspaceagent

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Ports, paths and object names shared by the agent, the workspace controller
// and the build API.
const (
	APIPort   = 9443
	FilesPort = 9091

	// InstallDir holds the agent binary in workspace pods. It is not under
	// /opt or /usr: the toolchain entrypoint mounts PVC overlays there,
	// which would hide it.
	InstallDir = "/ado"
	Binary     = InstallDir + "/workspace-agent"

	TokenDir = "/var/run/secrets/ado-agent"
	TokenKey = "token"
	TLSDir   = "/var/run/secrets/ado-agent-tls"
)

// ServiceName is the Service in front of a workspace's agent API. The serving
// certificate is issued for this name, so it must be a DNS label: names that
// don't fit use a digest of the workspace name instead. Digest names start
// with "ws-", which no other name does, so no workspace can be named into
// another's Service.
func ServiceName(workspace string) string {
	name := "workspace-" + workspace + "-agent"
	if len(name) <= 63 && !strings.Contains(name, ".") {
		return name
	}
	sum := sha256.Sum256([]byte(workspace))
	return "ws-" + hex.EncodeToString(sum[:8]) + "-agent"
}

// TLSSecretName is the Secret OpenShift's service CA fills with the agent's
// serving certificate.
func TLSSecretName(workspace string) string { return ServiceName(workspace) + "-tls" }

// TokenSecretName is the Secret holding the agent's bearer token.
func TokenSecretName(workspace string) string { return ServiceName(workspace) + "-token" }
