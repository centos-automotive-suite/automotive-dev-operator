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
	return serviceName("workspace-", workspace, "-agent", "ws-")
}

// TLSSecretName is the Secret OpenShift's service CA fills with the agent's
// serving certificate.
func TLSSecretName(workspace string) string { return ServiceName(workspace) + "-tls" }

// TokenSecretName is the Secret holding the agent's bearer token.
func TokenSecretName(workspace string) string { return ServiceName(workspace) + "-token" }

// UploadServiceName is the Service in front of the agent in a build's upload
// pod, named as ServiceName names a workspace's, with digest names that start
// with "ib-".
func UploadServiceName(build string) string {
	return serviceName("imagebuild-", build, "-upload", "ib-")
}

// UploadTLSSecretName is the Secret OpenShift's service CA fills with the
// upload agent's serving certificate.
func UploadTLSSecretName(build string) string { return UploadServiceName(build) + "-tls" }

// UploadTokenSecretName is the Secret holding the upload agent's bearer token.
func UploadTokenSecretName(build string) string { return UploadServiceName(build) + "-token" }

func serviceName(prefix, owner, suffix, digestPrefix string) string {
	name := prefix + owner + suffix
	if len(name) <= 63 && !strings.Contains(name, ".") {
		return name
	}
	sum := sha256.Sum256([]byte(owner))
	return digestPrefix + hex.EncodeToString(sum[:8]) + suffix
}
