package caibcommon

import (
	"testing"

	"github.com/containers/image/v5/types"
)

func TestReadManifestAnnotations_InvalidRef(t *testing.T) {
	_, _, err := ReadManifestAnnotations(":::invalid", &types.SystemContext{})
	if err == nil {
		t.Fatal("expected error for invalid reference")
	}
}

func TestNewRegistrySystemContext_InsecureTLS(t *testing.T) {
	sysCtx := NewRegistrySystemContext("quay.io/test/image:v1", true, "")
	if sysCtx.DockerInsecureSkipTLSVerify != types.OptionalBoolTrue {
		t.Error("expected InsecureSkipTLSVerify to be set")
	}
}

func TestNewRegistrySystemContext_SecureTLS(t *testing.T) {
	sysCtx := NewRegistrySystemContext("quay.io/test/image:v1", false, "")
	if sysCtx.DockerInsecureSkipTLSVerify == types.OptionalBoolTrue {
		t.Error("expected InsecureSkipTLSVerify to not be set")
	}
}

func TestNewRegistrySystemContext_AuthFile(t *testing.T) {
	sysCtx := NewRegistrySystemContext("quay.io/test/image:v1", false, "/tmp/auth.json")
	if sysCtx.AuthFilePath != "/tmp/auth.json" {
		t.Errorf("expected AuthFilePath = /tmp/auth.json, got %s", sysCtx.AuthFilePath)
	}
}

func TestNewRegistrySystemContext_EnvCredentials(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "testuser")
	t.Setenv("REGISTRY_PASSWORD", "testpass")

	sysCtx := NewRegistrySystemContext("quay.io/test/image:v1", false, "")
	if sysCtx.DockerAuthConfig == nil {
		t.Fatal("expected DockerAuthConfig to be set from env")
	}
	if sysCtx.DockerAuthConfig.Username != "testuser" {
		t.Errorf("expected username = testuser, got %s", sysCtx.DockerAuthConfig.Username)
	}
	if sysCtx.DockerAuthConfig.Password != "testpass" {
		t.Errorf("expected password = testpass, got %s", sysCtx.DockerAuthConfig.Password)
	}
}
