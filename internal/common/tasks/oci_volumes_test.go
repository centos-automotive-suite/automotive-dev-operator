package tasks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

const testOrasImage = "ghcr.io/oras-project/oras:v1.2.0"

func TestOCIVolumes_MountsOnBuildTask(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}
	task := GenerateBuildAutomotiveImageTask("test-ns", cfg, "")

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	for _, step := range task.Spec.Steps {
		assertHasVolumeMount(t, step.VolumeMounts, ociVolumeNameOras, ociMountPathOras)
	}
}

func TestOCIVolumes_ReturnedByOCIVolumes(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}

	vols := OCIVolumes(cfg)
	assertHasImageVolume(t, vols, ociVolumeNameOras, testOrasImage)
}

func TestOCIVolumes_AbsentWhenDisabled(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: false,
	}
	task := GenerateBuildAutomotiveImageTask("test-ns", cfg, "")

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	if vols := OCIVolumes(cfg); len(vols) != 0 {
		t.Fatal("OCIVolumes should return nil when disabled")
	}
}

func TestOCIVolumes_AbsentWhenNilConfig(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	if vols := OCIVolumes(nil); len(vols) != 0 {
		t.Fatal("OCIVolumes should return nil with nil config")
	}
}

func TestOCIVolumes_AbsentWhenEmptyImage(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     "",
	}
	task := GenerateBuildAutomotiveImageTask("test-ns", cfg, "")

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	if vols := OCIVolumes(cfg); len(vols) != 0 {
		t.Fatal("OCIVolumes should return nil when OrasImage is empty")
	}
}

func TestOCIVolumes_MountsOnPushTask(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}
	task := GeneratePushArtifactRegistryTask("test-ns", cfg)

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	for _, step := range task.Spec.Steps {
		assertHasVolumeMount(t, step.VolumeMounts, ociVolumeNameOras, ociMountPathOras)
	}
}

func TestOCIVolumes_AbsentOnSealedTask(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}
	task := GenerateSealedTaskForOperation("test-ns", "prepare", cfg)

	assertTaskHasNoVolume(t, task.Spec.Volumes)
	for _, step := range task.Spec.Steps {
		for _, vm := range step.VolumeMounts {
			if vm.Name == ociVolumeNameOras {
				t.Fatalf("sealed task step %q should not have OCI volume mount", step.Name)
			}
		}
	}
}

func TestOCIVolumes_ReadOnly(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}
	task := GenerateBuildAutomotiveImageTask("test-ns", cfg, "")

	for _, step := range task.Spec.Steps {
		for _, vm := range step.VolumeMounts {
			if vm.Name == ociVolumeNameOras && !vm.ReadOnly {
				t.Fatalf("ORAS volume mount on step %q should be read-only", step.Name)
			}
		}
	}
}

func TestOCIVolumes_PullPolicy(t *testing.T) {
	cfg := &BuildConfig{
		UseOCIVolumes: true,
		OrasImage:     testOrasImage,
	}

	vols := OCIVolumes(cfg)
	for _, vol := range vols {
		if vol.Name == ociVolumeNameOras {
			if vol.Image == nil {
				t.Fatal("ORAS volume should use Image volume source")
			}
			if vol.Image.PullPolicy != corev1.PullIfNotPresent {
				t.Fatalf("ORAS volume pull policy = %v, want IfNotPresent", vol.Image.PullPolicy)
			}
		}
	}
}

func assertHasImageVolume(t *testing.T, volumes []corev1.Volume, name, reference string) {
	t.Helper()
	for _, vol := range volumes {
		if vol.Name == name {
			if vol.Image == nil {
				t.Fatalf("volume %q exists but is not an Image volume", name)
			}
			if vol.Image.Reference != reference {
				t.Fatalf("volume %q reference = %q, want %q", name, vol.Image.Reference, reference)
			}
			return
		}
	}
	t.Fatalf("image volume %q not found", name)
}

func assertTaskHasNoVolume(t *testing.T, volumes []corev1.Volume) {
	t.Helper()
	for _, vol := range volumes {
		if vol.Name == ociVolumeNameOras {
			t.Fatalf("volume %q should not be on Task spec (belongs in podTemplate)", vol.Name)
		}
	}
}

func assertHasVolumeMount(t *testing.T, mounts []corev1.VolumeMount, name, path string) {
	t.Helper()
	for _, vm := range mounts {
		if vm.Name == name {
			if vm.MountPath != path {
				t.Fatalf("volume mount %q path = %q, want %q", name, vm.MountPath, path)
			}
			return
		}
	}
	t.Fatalf("volume mount %q not found", name)
}
