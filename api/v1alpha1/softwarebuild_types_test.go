package v1alpha1

import (
	"encoding/json"
	"testing"
)

func TestSoftwareBuildSpec_JSONRoundTrip(t *testing.T) {
	original := SoftwareBuild{
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

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTripped SoftwareBuild
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundTripped.Spec.Runtime.Image != original.Spec.Runtime.Image {
		t.Errorf("image: got %q, want %q", roundTripped.Spec.Runtime.Image, original.Spec.Runtime.Image)
	}
	if roundTripped.Spec.Source.Type != SoftwareBuildSourceGit {
		t.Errorf("source type: got %q, want %q", roundTripped.Spec.Source.Type, SoftwareBuildSourceGit)
	}
	if roundTripped.Spec.Source.Git == nil || roundTripped.Spec.Source.Git.URL != "https://github.com/vtz/body-ecu" {
		t.Errorf("git URL not preserved through round-trip")
	}
	if roundTripped.Spec.Stages.Build.Command != "west build -b native_sim app" {
		t.Errorf("build command: got %q", roundTripped.Spec.Stages.Build.Command)
	}
	if roundTripped.Spec.TimeoutSeconds != 1800 {
		t.Errorf("timeout: got %d, want 1800", roundTripped.Spec.TimeoutSeconds)
	}
	if roundTripped.Spec.Destination.Type != SoftwareBuildDestSharedFolder {
		t.Errorf("destination type: got %q, want %q", roundTripped.Spec.Destination.Type, SoftwareBuildDestSharedFolder)
	}
}

func TestSoftwareBuildSpec_PVCSource_JSONRoundTrip(t *testing.T) {
	original := SoftwareBuild{
		Spec: SoftwareBuildSpec{
			Source: SoftwareBuildSourceSpec{
				Type: SoftwareBuildSourcePVC,
				PVC:  &SoftwareBuildPVCSource{ClaimName: "my-pvc", Path: "/data"},
			},
			Stages: SoftwareBuildPipelineStages{
				Fetch: SoftwareBuildStageSpec{Command: "echo fetched"},
				Build: SoftwareBuildStageSpec{Command: "make"},
			},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTripped SoftwareBuild
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundTripped.Spec.Source.Type != SoftwareBuildSourcePVC {
		t.Errorf("source type: got %q, want pvc", roundTripped.Spec.Source.Type)
	}
	if roundTripped.Spec.Source.PVC == nil {
		t.Fatal("PVC source lost during round-trip")
	}
	if roundTripped.Spec.Source.PVC.ClaimName != "my-pvc" {
		t.Errorf("claimName: got %q, want my-pvc", roundTripped.Spec.Source.PVC.ClaimName)
	}
	if roundTripped.Spec.Source.Git != nil {
		t.Error("git source should be nil for PVC source type")
	}
}

func TestSoftwareBuildStatus_JSONRoundTrip(t *testing.T) {
	original := SoftwareBuildStatus{
		Phase:           SoftwareBuildPhaseSucceeded,
		PipelineRunName: "build-gen1",
		ArtifactURI:     "/workspace/artifacts",
		Stages: []SoftwareBuildStageStatus{
			{Name: "fetch", State: "Completed"},
			{Name: "build", State: "Completed"},
		},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	var roundTripped SoftwareBuildStatus
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if roundTripped.Phase != SoftwareBuildPhaseSucceeded {
		t.Errorf("phase: got %q, want Succeeded", roundTripped.Phase)
	}
	if roundTripped.PipelineRunName != "build-gen1" {
		t.Errorf("pipelineRunName: got %q", roundTripped.PipelineRunName)
	}
	if len(roundTripped.Stages) != 2 {
		t.Fatalf("stages: got %d, want 2", len(roundTripped.Stages))
	}
	if roundTripped.Stages[1].Name != "build" {
		t.Errorf("stage[1] name: got %q, want build", roundTripped.Stages[1].Name)
	}
}
