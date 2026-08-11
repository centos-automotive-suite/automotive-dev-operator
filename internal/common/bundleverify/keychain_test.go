package bundleverify

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestKeychainFromPullSecrets_EmptyReturnsDefault(t *testing.T) {
	kc, err := KeychainFromPullSecrets(context.Background(), newFakeReader(), "default", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kc != authn.DefaultKeychain {
		t.Fatal("expected DefaultKeychain for empty secrets")
	}
}

func TestKeychainFromPullSecrets_MissingSecretReturnsError(t *testing.T) {
	secrets := []corev1.LocalObjectReference{{Name: "nonexistent"}}
	_, err := KeychainFromPullSecrets(context.Background(), newFakeReader(), "default", secrets)
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}

func TestKeychainFromPullSecrets_SkipsNonDockerSecret(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "opaque-secret", Namespace: "default"},
		Data:       map[string][]byte{"some-key": []byte("some-value")},
	}
	secrets := []corev1.LocalObjectReference{{Name: "opaque-secret"}}
	kc, err := KeychainFromPullSecrets(context.Background(), newFakeReader(secret), "default", secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should still return a keychain (multi with just DefaultKeychain)
	if kc == nil {
		t.Fatal("expected non-nil keychain")
	}
}

func TestKeychainFromPullSecrets_ResolvesDockerConfigJSON(t *testing.T) {
	dockerCfg := map[string]any{
		"auths": map[string]any{
			"registry.example.com": map[string]string{
				"username": "testuser",
				"password": "testpass",
			},
		},
	}
	cfgBytes, _ := json.Marshal(dockerCfg)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: "default"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: cfgBytes},
	}
	secrets := []corev1.LocalObjectReference{{Name: "my-pull-secret"}}
	kc, err := KeychainFromPullSecrets(context.Background(), newFakeReader(secret), "default", secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reg, err := name.NewRegistry("registry.example.com")
	if err != nil {
		t.Fatalf("bad registry: %v", err)
	}
	auth, err := kc.Resolve(reg)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	cfg, err := auth.Authorization()
	if err != nil {
		t.Fatalf("authorization error: %v", err)
	}
	if cfg.Username != "testuser" || cfg.Password != "testpass" {
		t.Errorf("got user=%q pass=%q, want testuser/testpass", cfg.Username, cfg.Password)
	}
}

func TestKeychainFromPullSecrets_UnknownRegistryFallsThrough(t *testing.T) {
	dockerCfg := map[string]any{
		"auths": map[string]any{
			"registry.example.com": map[string]string{
				"username": "testuser",
				"password": "testpass",
			},
		},
	}
	cfgBytes, _ := json.Marshal(dockerCfg)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-pull-secret", Namespace: "default"},
		Type:       corev1.SecretTypeDockerConfigJson,
		Data:       map[string][]byte{corev1.DockerConfigJsonKey: cfgBytes},
	}
	secrets := []corev1.LocalObjectReference{{Name: "my-pull-secret"}}
	kc, err := KeychainFromPullSecrets(context.Background(), newFakeReader(secret), "default", secrets)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	reg, _ := name.NewRegistry("other-registry.io")
	auth, err := kc.Resolve(reg)
	if err != nil {
		t.Fatalf("resolve error: %v", err)
	}
	// Should get Anonymous from the pull secret keychain, then fall through to DefaultKeychain
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}
}
