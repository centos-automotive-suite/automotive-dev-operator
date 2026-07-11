package tasks

import (
	"fmt"
	"testing"
)

const buildImageStepName = "build-image"

func TestOCIRepoVolumes_PresentAsEmptyDir(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	found := 0
	for _, vol := range task.Spec.Volumes {
		for i := 0; i < OCIRepoVolumeCount; i++ {
			name := fmt.Sprintf("oci-repo-%d", i)
			if vol.Name == name {
				if vol.EmptyDir == nil {
					t.Fatalf("volume %q should be EmptyDir", name)
				}
				if vol.EmptyDir.Medium != "" {
					t.Fatalf("volume %q should be disk-backed (no medium), got %q", name, vol.EmptyDir.Medium)
				}
				found++
			}
		}
	}
	if found != OCIRepoVolumeCount {
		t.Fatalf("expected %d oci-repo volumes, found %d", OCIRepoVolumeCount, found)
	}
}

func TestOCIRepoVolumes_MountedReadOnlyOnBuildStep(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	for _, step := range task.Spec.Steps {
		if step.Name != buildImageStepName {
			continue
		}

		found := 0
		for _, vm := range step.VolumeMounts {
			for i := 0; i < OCIRepoVolumeCount; i++ {
				name := OCIRepoVolumeName(i)
				expectedPath := OCIRepoMountBase + name
				if vm.Name == name {
					if vm.MountPath != expectedPath {
						t.Fatalf("volume mount %q: expected mountPath %q, got %q", name, expectedPath, vm.MountPath)
					}
					if !vm.ReadOnly {
						t.Fatalf("volume mount %q should be readOnly", name)
					}
					found++
				}
			}
		}
		if found != OCIRepoVolumeCount {
			t.Fatalf("expected %d oci-repo volume mounts on build-image step, found %d", OCIRepoVolumeCount, found)
		}
		return
	}
	t.Fatal("build-image step not found")
}

func TestOCIRepoVolumes_NotOnOtherSteps(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, step := range task.Spec.Steps {
		if step.Name == buildImageStepName {
			continue
		}
		for _, vm := range step.VolumeMounts {
			if ociNames[vm.Name] {
				t.Fatalf("step %q should not have oci-repo volume mount %q", step.Name, vm.Name)
			}
		}
	}
}

func TestOCIRepoVolumes_NilBuildConfig(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	found := 0
	for _, vol := range task.Spec.Volumes {
		for i := 0; i < OCIRepoVolumeCount; i++ {
			if vol.Name == fmt.Sprintf("oci-repo-%d", i) {
				if vol.EmptyDir == nil {
					t.Fatalf("oci-repo-%d should be EmptyDir with nil config", i)
				}
				found++
			}
		}
	}
	if found != OCIRepoVolumeCount {
		t.Fatalf("expected %d oci-repo volumes with nil config, found %d", OCIRepoVolumeCount, found)
	}
}

func TestOCIRepoVolumes_UntouchedByMemoryVolumes(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes: true,
		MemoryVolumeSize: "8Gi",
	}, "")

	for _, vol := range task.Spec.Volumes {
		for i := 0; i < OCIRepoVolumeCount; i++ {
			name := fmt.Sprintf("oci-repo-%d", i)
			if vol.Name == name {
				if vol.EmptyDir == nil {
					t.Fatalf("oci-repo volume %q should remain EmptyDir", name)
				}
				if vol.EmptyDir.Medium != "" {
					t.Fatalf("oci-repo volume %q should not get memory medium, got %q", name, vol.EmptyDir.Medium)
				}
				if vol.EmptyDir.SizeLimit != nil {
					t.Fatalf("oci-repo volume %q should not get sizeLimit", name)
				}
			}
		}
	}
}

func TestOCIRepoVolumes_UntouchedByPVCScratch(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	found := 0
	for _, vol := range task.Spec.Volumes {
		for i := 0; i < OCIRepoVolumeCount; i++ {
			name := fmt.Sprintf("oci-repo-%d", i)
			if vol.Name == name {
				if vol.EmptyDir == nil {
					t.Fatalf("oci-repo volume %q should remain EmptyDir when PVC scratch is on", name)
				}
				found++
			}
		}
	}
	if found != OCIRepoVolumeCount {
		t.Fatalf("expected %d oci-repo volumes preserved with PVC scratch, found %d", OCIRepoVolumeCount, found)
	}

	// Volume mounts on build-image should still reference oci-repo volumes directly
	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, step := range task.Spec.Steps {
		if step.Name != buildImageStepName {
			continue
		}
		mountFound := 0
		for _, vm := range step.VolumeMounts {
			if ociNames[vm.Name] {
				if vm.SubPath != "" {
					t.Fatalf("oci-repo mount %q should not have subPath set by PVC scratch redirect", vm.Name)
				}
				if vm.Name == workspaceVolumeRef {
					t.Fatalf("oci-repo mount should not be rewritten to workspace volume ref")
				}
				mountFound++
			}
		}
		if mountFound != OCIRepoVolumeCount {
			t.Fatalf("expected %d oci-repo mounts on build-image step with PVC scratch, found %d", OCIRepoVolumeCount, mountFound)
		}
	}
}

func TestOCIRepoVolumes_CombinedMemoryAndPVCScratch(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes:     true,
		UsePVCScratchVolumes: true,
		MemoryVolumeSize:     "8Gi",
	}, "")

	for _, vol := range task.Spec.Volumes {
		for i := 0; i < OCIRepoVolumeCount; i++ {
			name := fmt.Sprintf("oci-repo-%d", i)
			if vol.Name == name {
				if vol.EmptyDir == nil {
					t.Fatalf("oci-repo volume %q should remain EmptyDir", name)
				}
				if vol.EmptyDir.Medium != "" {
					t.Fatalf("oci-repo volume %q should not get memory medium even with both flags", name)
				}
			}
		}
	}
}
