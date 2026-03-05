package tasks

import (
	"testing"
)

const customCAVolumeName = "custom-ca"

func TestTrustedCABundleVolumeSource_DefaultsToConfigMap(t *testing.T) {
	src := trustedCABundleVolumeSource(nil)

	if src.ConfigMap == nil {
		t.Fatalf("expected ConfigMap source by default")
	}
	if src.ConfigMap.Name != defaultTrustedCABundleConfigMap {
		t.Fatalf("expected default configmap %q, got %q", defaultTrustedCABundleConfigMap, src.ConfigMap.Name)
	}
}

func TestTrustedCABundleVolumeSource_UsesSecretWhenConfigured(t *testing.T) {
	src := trustedCABundleVolumeSource(&BuildConfig{
		TrustedCABundleKind: "Secret",
		TrustedCABundleName: "my-test-ca-secret",
	})

	if src.Secret == nil {
		t.Fatalf("expected Secret source")
	}
	if src.Secret.SecretName != "my-test-ca-secret" {
		t.Fatalf("expected secret name my-test-ca-secret, got %q", src.Secret.SecretName)
	}
}

func TestGenerateSealedTaskForOperation_UsesConfiguredTrustedCABundle(t *testing.T) {
	task := GenerateSealedTaskForOperation("test-ns", "reseal", &BuildConfig{
		TrustedCABundleKind: "ConfigMap",
		TrustedCABundleName: "my-test-ca",
	})

	for _, vol := range task.Spec.Volumes {
		if vol.Name != customCAVolumeName {
			continue
		}
		if vol.ConfigMap == nil {
			t.Fatalf("expected custom-ca volume to be configmap-backed")
		}
		if vol.ConfigMap.Name != "my-test-ca" {
			t.Fatalf("expected custom-ca configmap name my-test-ca, got %q", vol.ConfigMap.Name)
		}
		return
	}

	t.Fatalf("%s volume not found in generated sealed task", customCAVolumeName)
}

func TestGenerateBuildAutomotiveImageTask_UsesConfiguredTrustedCABundle(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		TrustedCABundleKind: "Secret",
		TrustedCABundleName: "my-test-ca-secret",
	}, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name != customCAVolumeName {
			continue
		}
		if vol.Secret == nil {
			t.Fatalf("expected custom-ca volume to be secret-backed")
		}
		if vol.Secret.SecretName != "my-test-ca-secret" {
			t.Fatalf("expected custom-ca secret name my-test-ca-secret, got %q", vol.Secret.SecretName)
		}
		return
	}

	t.Fatalf("%s volume not found in generated build task", customCAVolumeName)
}

func TestGeneratePushArtifactRegistryTask_NoCustomCABundleVolume(t *testing.T) {
	task := GeneratePushArtifactRegistryTask("test-ns", &BuildConfig{
		TrustedCABundleKind: "",
		TrustedCABundleName: "ignored",
	})
	for _, vol := range task.Spec.Volumes {
		if vol.Name == customCAVolumeName {
			t.Fatalf("push-artifact-registry task should not include %s volume", customCAVolumeName)
		}
	}
}
