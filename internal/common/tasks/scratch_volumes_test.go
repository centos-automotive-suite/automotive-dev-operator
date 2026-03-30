package tasks

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// pvcScratchVolumeNames are the volumes moved to PVC.
// container-storage is excluded because overlay storage driver needs tmpfs/node disk.
var pvcScratchVolumeNames = map[string]bool{
	"build-dir":  true,
	"output-dir": true,
	"run-dir":    true,
}

var pvcScratchMountPaths = map[string]bool{
	"/_build":      true,
	"/output":      true,
	"/run/osbuild": true,
}

// allScratchVolumeNames includes container-storage for memory volume tests
var allScratchVolumeNames = map[string]bool{
	"build-dir":                true,
	"output-dir":               true,
	"run-dir":                  true,
	volumeNameContainerStorage: true,
}

func TestPVCScratchVolumes_RemovesEmptyDirVolumes(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	for _, vol := range task.Spec.Volumes {
		if pvcScratchVolumeNames[vol.Name] {
			t.Fatalf("scratch volume %q should have been removed when UsePVCScratchVolumes is true", vol.Name)
		}
	}
}

func TestPVCScratchVolumes_KeepsContainerStorage(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	found := false
	for _, vol := range task.Spec.Volumes {
		if vol.Name == volumeNameContainerStorage {
			found = true
			if vol.EmptyDir == nil {
				t.Fatal("container-storage should remain as emptyDir")
			}
		}
	}
	if !found {
		t.Fatal("container-storage volume should be preserved (overlay driver needs tmpfs/node disk)")
	}
}

func TestPVCScratchVolumes_RewritesVolumeMountsToWorkspace(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	expectedSubPaths := map[string]string{
		"/_build":      "scratch-build",
		"/output":      "scratch-output",
		"/run/osbuild": "scratch-run",
	}

	for _, step := range task.Spec.Steps {
		for _, vm := range step.VolumeMounts {
			if subPath, ok := expectedSubPaths[vm.MountPath]; ok {
				if vm.Name != workspaceVolumeRef {
					t.Fatalf("step %q mount at %s should reference workspace volume, got %q", step.Name, vm.MountPath, vm.Name)
				}
				if vm.SubPath != subPath {
					t.Fatalf("step %q mount at %s should have subPath %q, got %q", step.Name, vm.MountPath, subPath, vm.SubPath)
				}
			}
		}
	}
}

func TestPVCScratchVolumes_NoEmptyDirVolumeMountsOnSteps(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	for _, step := range task.Spec.Steps {
		for _, vm := range step.VolumeMounts {
			if pvcScratchVolumeNames[vm.Name] {
				t.Fatalf("step %q still has volumeMount for removed scratch volume %q", step.Name, vm.Name)
			}
		}
	}
}

func TestPVCScratchVolumes_PreservesNonScratchVolumes(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	if len(task.Spec.Volumes) == 0 {
		t.Fatal("all volumes were removed; non-scratch volumes should be preserved")
	}

	// dev and sysfs host path volumes should still exist
	hostPathFound := map[string]bool{}
	for _, vol := range task.Spec.Volumes {
		if vol.HostPath != nil {
			hostPathFound[vol.Name] = true
		}
	}
	for _, name := range []string{"dev", "sysfs"} {
		if !hostPathFound[name] {
			t.Fatalf("host path volume %q should be preserved", name)
		}
	}
}

func TestMemoryVolumes_SetsMediaToMemory(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes: true,
	}, "")

	for _, vol := range task.Spec.Volumes {
		if allScratchVolumeNames[vol.Name] {
			if vol.EmptyDir == nil {
				t.Fatalf("volume %q should be emptyDir", vol.Name)
			}
			if vol.EmptyDir.Medium != corev1.StorageMediumMemory {
				t.Fatalf("volume %q should have medium Memory, got %q", vol.Name, vol.EmptyDir.Medium)
			}
		}
	}
}

func TestMemoryVolumes_SetsSizeLimit(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes: true,
		MemoryVolumeSize: "8Gi",
	}, "")

	for _, vol := range task.Spec.Volumes {
		if allScratchVolumeNames[vol.Name] {
			if vol.EmptyDir == nil || vol.EmptyDir.SizeLimit == nil {
				t.Fatalf("volume %q should have a sizeLimit set", vol.Name)
			}
			if vol.EmptyDir.SizeLimit.String() != "8Gi" {
				t.Fatalf("volume %q sizeLimit expected 8Gi, got %s", vol.Name, vol.EmptyDir.SizeLimit.String())
			}
		}
	}
}

func TestPVCScratchVolumes_TakesPrecedenceOverMemory(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes:     true,
		UsePVCScratchVolumes: true,
	}, "")

	// PVC scratch volumes should be gone (PVC wins), container-storage stays
	for _, vol := range task.Spec.Volumes {
		if pvcScratchVolumeNames[vol.Name] {
			t.Fatalf("scratch volume %q should be removed when UsePVCScratchVolumes is true, even with UseMemoryVolumes", vol.Name)
		}
	}

	// container-storage should still be present and get memory medium
	found := false
	for _, vol := range task.Spec.Volumes {
		if vol.Name == volumeNameContainerStorage {
			found = true
			if vol.EmptyDir == nil || vol.EmptyDir.Medium != corev1.StorageMediumMemory {
				t.Fatal("container-storage should have memory medium when useMemoryVolumes is true")
			}
		}
	}
	if !found {
		t.Fatal("container-storage volume should be preserved when both useMemoryVolumes and usePVCScratchVolumes are true")
	}

	// Steps that had scratch mounts should now reference workspace volume
	totalFound := 0
	for _, step := range task.Spec.Steps {
		for _, vm := range step.VolumeMounts {
			if vm.Name == workspaceVolumeRef && vm.SubPath != "" {
				totalFound++
			}
		}
	}
	if totalFound == 0 {
		t.Fatal("no workspace volume mounts found in any step")
	}
}

func TestDefaultConfig_UsesDiskBackedEmptyDir(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	found := 0
	for _, vol := range task.Spec.Volumes {
		if allScratchVolumeNames[vol.Name] {
			if vol.EmptyDir == nil {
				t.Fatalf("volume %q should be emptyDir by default", vol.Name)
			}
			if vol.EmptyDir.Medium != "" {
				t.Fatalf("volume %q should be disk-backed by default, got medium %q", vol.Name, vol.EmptyDir.Medium)
			}
			found++
		}
	}
	if found != len(allScratchVolumeNames) {
		t.Fatalf("expected %d scratch volumes, found %d", len(allScratchVolumeNames), found)
	}
}

func TestNilBuildConfig_UsesDiskBackedEmptyDir(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	for _, vol := range task.Spec.Volumes {
		if allScratchVolumeNames[vol.Name] {
			if vol.EmptyDir == nil {
				t.Fatalf("volume %q should be emptyDir with nil config", vol.Name)
			}
			if vol.EmptyDir.Medium != "" {
				t.Fatalf("volume %q should be disk-backed with nil config", vol.Name)
			}
		}
	}
}

func TestPVCScratchVolumes_BuildStepRewritten(t *testing.T) {
	// Verify volume mounts are rewritten in steps that use scratch dirs
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	if len(task.Spec.Steps) == 0 {
		t.Fatal("task has no steps")
	}

	// The build-image step should have workspace volume mounts
	for _, step := range task.Spec.Steps {
		if step.Name != "build-image" {
			continue
		}
		found := 0
		for _, vm := range step.VolumeMounts {
			if vm.Name == workspaceVolumeRef && vm.SubPath != "" {
				found++
			}
		}
		if found != len(pvcScratchMountPaths) {
			t.Fatalf("build-image step: expected %d workspace volume mounts, got %d", len(pvcScratchMountPaths), found)
		}
		return
	}
	t.Fatal("build-image step not found")
}

// Tests for GetUsePVCScratchVolumes are in the api package
// but we verify the BuildConfig bool integration here
func TestBuildConfig_PVCScratchDefaultFalse(t *testing.T) {
	cfg := &BuildConfig{}
	if cfg.UsePVCScratchVolumes {
		t.Fatal("UsePVCScratchVolumes should default to false on BuildConfig")
	}
}

func TestBuildConfig_PVCScratchExplicitTrue(t *testing.T) {
	cfg := &BuildConfig{UsePVCScratchVolumes: true}
	if !cfg.UsePVCScratchVolumes {
		t.Fatal("UsePVCScratchVolumes should be true when set")
	}
}
