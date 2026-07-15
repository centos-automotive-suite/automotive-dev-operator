package tasks

import (
	"testing"
)

const buildImageStepName = PipelineTaskBuildImage

func TestOCIRepoVolumes_NotDeclaredInTask(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name == OCIRepoVolumeName {
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
		for _, vm := range step.VolumeMounts {
			if vm.Name == OCIRepoVolumeName {
				if vm.MountPath != OCIRepoMountPath {
					t.Fatalf("volume mount %q: expected mountPath %q, got %q", vm.Name, OCIRepoMountPath, vm.MountPath)
				}
				if !vm.ReadOnly {
					t.Fatalf("volume mount %q should be readOnly", vm.Name)
				}
				return
			}
		}
		t.Fatal("oci-repo volume mount not found on build-image step")
	}
	t.Fatal("build-image step not found")
}

func TestOCIRepoVolumes_NotOnOtherSteps(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{}, "")

	for _, step := range task.Spec.Steps {
		if step.Name == buildImageStepName {
			continue
		}
		for _, vm := range step.VolumeMounts {
			if vm.Name == OCIRepoVolumeName {
				t.Fatalf("step %q should not have oci-repo volume mount", step.Name)
			}
		}
	}
}

func TestOCIRepoVolumes_NilBuildConfig(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", nil, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name == OCIRepoVolumeName {
			t.Fatalf("Task should not declare volume %q even with nil config", vol.Name)
		}
	}
}

func TestOCIRepoVolumes_NotAffectedByMemoryVolumes(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes: true,
		MemoryVolumeSize: "8Gi",
	}, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name == OCIRepoVolumeName {
			t.Fatalf("oci-repo volume should not be declared in Task with memory volumes")
		}
	}

	for _, step := range task.Spec.Steps {
		if step.Name != buildImageStepName {
			continue
		}
		for _, vm := range step.VolumeMounts {
			if vm.Name == OCIRepoVolumeName {
				if !vm.ReadOnly {
					t.Fatalf("oci-repo mount should be readOnly")
				}
				return
			}
		}
		t.Fatal("oci-repo mount not found on build-image step with memory volumes")
	}
}

func TestOCIRepoVolumes_NotAffectedByPVCScratch(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UsePVCScratchVolumes: true,
	}, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name == OCIRepoVolumeName {
			t.Fatalf("oci-repo volume should not be declared in Task with PVC scratch")
		}
	}

	for _, step := range task.Spec.Steps {
		if step.Name != buildImageStepName {
			continue
		}
		for _, vm := range step.VolumeMounts {
			if vm.Name == OCIRepoVolumeName {
				if vm.SubPath != "" {
					t.Fatalf("oci-repo mount should not have subPath set by PVC scratch redirect")
				}
				return
			}
		}
		t.Fatal("oci-repo mount not found on build-image step with PVC scratch")
	}
}

func TestOCIRepoVolumes_CombinedMemoryAndPVCScratch(t *testing.T) {
	task := GenerateBuildAutomotiveImageTask("test-ns", &BuildConfig{
		UseMemoryVolumes:     true,
		UsePVCScratchVolumes: true,
		MemoryVolumeSize:     "8Gi",
	}, "")

	for _, vol := range task.Spec.Volumes {
		if vol.Name == OCIRepoVolumeName {
			t.Fatalf("oci-repo volume should not be declared in Task even with both flags")
		}
	}
}
