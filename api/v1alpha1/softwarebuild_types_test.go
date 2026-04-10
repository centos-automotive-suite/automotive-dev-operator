package v1alpha1

import (
	"testing"
)

func TestSoftwareBuildDefaultImage(t *testing.T) {
	sb := SoftwareBuild{
		Spec: SoftwareBuildSpec{
			Runtime: SoftwareBuildRuntimeSpec{},
		},
	}
	if sb.Spec.Runtime.Image != "" {
		t.Errorf("expected empty image before kubebuilder defaulting, got %q", sb.Spec.Runtime.Image)
	}
}

func TestSoftwareBuildPhaseConstants(t *testing.T) {
	phases := []SoftwareBuildPhase{
		SoftwareBuildPhasePending,
		SoftwareBuildPhaseRunning,
		SoftwareBuildPhaseSucceeded,
		SoftwareBuildPhaseFailed,
	}
	expected := []string{"Pending", "Running", "Succeeded", "Failed"}
	for i, p := range phases {
		if string(p) != expected[i] {
			t.Errorf("phase %d: got %q, want %q", i, p, expected[i])
		}
	}
}

func TestSoftwareBuildSourceTypeConstants(t *testing.T) {
	if SoftwareBuildSourceGit != "git" {
		t.Errorf("expected git, got %q", SoftwareBuildSourceGit)
	}
	if SoftwareBuildSourcePVC != "pvc" {
		t.Errorf("expected pvc, got %q", SoftwareBuildSourcePVC)
	}
	if SoftwareBuildSourceHostPath != "hostPath" {
		t.Errorf("expected hostPath, got %q", SoftwareBuildSourceHostPath)
	}
}

func TestSoftwareBuildDestinationTypeConstants(t *testing.T) {
	if SoftwareBuildDestSharedFolder != "sharedFolder" {
		t.Errorf("expected sharedFolder, got %q", SoftwareBuildDestSharedFolder)
	}
	if SoftwareBuildDestRegistry != "registry" {
		t.Errorf("expected registry, got %q", SoftwareBuildDestRegistry)
	}
}

func TestSoftwareBuildSpecStructure(t *testing.T) {
	sb := SoftwareBuild{
		Spec: SoftwareBuildSpec{
			Runtime: SoftwareBuildRuntimeSpec{Image: "ghcr.io/zephyrproject-rtos/ci-base:latest"},
			Source: SoftwareBuildSourceSpec{
				Type: SoftwareBuildSourceGit,
				Git: &SoftwareBuildGitSource{
					URL:      "https://github.com/vtz/body-ecu",
					Revision: "main",
				},
			},
			Stages: SoftwareBuildPipelineStages{
				Fetch:     SoftwareBuildStageSpec{Command: "west init -l . && west update"},
				Prebuild:  SoftwareBuildStageSpec{Command: "echo prebuild"},
				Build:     SoftwareBuildStageSpec{Command: "west build -b native_sim app"},
				Postbuild: SoftwareBuildStageSpec{Command: "ctest --test-dir build/tests"},
				Deploy:    SoftwareBuildStageSpec{Command: "cp build/zephyr/zephyr.elf /out/"},
			},
			Destination: SoftwareBuildDestinationSpec{
				Type: SoftwareBuildDestSharedFolder,
				Path: "/out",
			},
			TimeoutSeconds: 1800,
		},
	}

	if sb.Spec.Runtime.Image != "ghcr.io/zephyrproject-rtos/ci-base:latest" {
		t.Errorf("unexpected runtime image: %s", sb.Spec.Runtime.Image)
	}
	if sb.Spec.Source.Git.URL != "https://github.com/vtz/body-ecu" {
		t.Errorf("unexpected git URL: %s", sb.Spec.Source.Git.URL)
	}
	if sb.Spec.Stages.Build.Command != "west build -b native_sim app" {
		t.Errorf("unexpected build command: %s", sb.Spec.Stages.Build.Command)
	}
	if sb.Spec.TimeoutSeconds != 1800 {
		t.Errorf("unexpected timeout: %d", sb.Spec.TimeoutSeconds)
	}
}
