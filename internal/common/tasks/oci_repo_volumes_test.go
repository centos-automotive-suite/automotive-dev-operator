package tasks

import (
	"fmt"
	"testing"
)

const buildImageStepName = "build-image"

func TestOCIRepoVolumes_NotDeclaredInTask(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, vol := range task.Spec.Volumes {
		if ociNames[vol.Name] {
			t.Fatalf("Task should not declare volume %q — volumes are provided at PipelineRun time", vol.Name)
		}
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

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, vol := range task.Spec.Volumes {
		if ociNames[vol.Name] {
			t.Fatalf("Task should not declare volume %q even with nil config", vol.Name)
		}
	}
}

func TestOCIRepoVolumes_NotAffectedByMemoryVolumes(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes: true,
		MemoryVolumeSize: "8Gi",
	}, "")

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, vol := range task.Spec.Volumes {
		if ociNames[vol.Name] {
			t.Fatalf("oci-repo volume %q should not be declared in Task with memory volumes", vol.Name)
		}
	}

	for _, step := range task.Spec.Steps {
		if step.Name != buildImageStepName {
			continue
		}
		found := 0
		for _, vm := range step.VolumeMounts {
			if ociNames[vm.Name] {
				if !vm.ReadOnly {
					t.Fatalf("oci-repo mount %q should be readOnly", vm.Name)
				}
				found++
			}
		}
		if found != OCIRepoVolumeCount {
			t.Fatalf("expected %d oci-repo mounts, found %d", OCIRepoVolumeCount, found)
		}
	}
}

func TestOCIRepoVolumes_NotAffectedByPVCScratch(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, vol := range task.Spec.Volumes {
		if ociNames[vol.Name] {
			t.Fatalf("oci-repo volume %q should not be declared in Task with PVC scratch", vol.Name)
		}
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

	ociNames := make(map[string]bool)
	for i := 0; i < OCIRepoVolumeCount; i++ {
		ociNames[fmt.Sprintf("oci-repo-%d", i)] = true
	}

	for _, vol := range task.Spec.Volumes {
		if ociNames[vol.Name] {
			t.Fatalf("oci-repo volume %q should not be declared in Task even with both flags", vol.Name)
		}
	}
}
