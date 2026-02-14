package main

import (
	"testing"

	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/spf13/cobra"
)

func newCmdWithArchFlag(archValue string, changed bool) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringP("arch", "a", archAMD64, "architecture")
	if changed {
		// Simulate the user explicitly setting the flag
		if err := cmd.Flags().Set("arch", archValue); err != nil {
			panic(err)
		}
	}
	return cmd
}

func TestApplyTargetDefaults_NilConfig(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, nil, req)

	if req.Architecture != buildapitypes.Architecture(archAMD64) {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_EmptyTargets(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archAMD64) {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_NoMatchingTarget(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"qemu": {},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archAMD64) {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_AppliesArchFromMapping(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ebbr": {
				Architecture: archARM64,
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archARM64) {
		t.Errorf("expected architecture to be overridden to arm64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_ExplicitArchOverridesMapping(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, true) // user explicitly set --arch amd64
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ebbr": {
				Architecture: archARM64,
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archAMD64) {
		t.Errorf("expected explicit --arch to override mapping, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_ExplicitArchArm64OverridesMapping(t *testing.T) {
	cmd := newCmdWithArchFlag(archARM64, true) // user explicitly set --arch arm64
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ebbr": {
				Architecture: archAMD64, // mapping says amd64
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ebbr",
		Architecture: buildapitypes.Architecture(archARM64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archARM64) {
		t.Errorf("expected explicit --arch arm64 to override mapping amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_PrependsExtraArgs(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ride": {
				ExtraArgs: []string{"--separate-partitions"},
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ride",
		Architecture: buildapitypes.Architecture(archAMD64),
		AIBExtraArgs: []string{"--user-arg"},
	}

	applyTargetDefaults(cmd, config, req)

	expected := []string{"--separate-partitions", "--user-arg"}
	if len(req.AIBExtraArgs) != len(expected) {
		t.Fatalf("expected %d extra args, got %d: %v", len(expected), len(req.AIBExtraArgs), req.AIBExtraArgs)
	}
	for i, arg := range expected {
		if req.AIBExtraArgs[i] != arg {
			t.Errorf("extra arg [%d]: expected %q, got %q", i, arg, req.AIBExtraArgs[i])
		}
	}
}

func TestApplyTargetDefaults_ExtraArgsWithNoUserArgs(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ride": {
				ExtraArgs: []string{"--separate-partitions", "--verbose"},
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ride",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	expected := []string{"--separate-partitions", "--verbose"}
	if len(req.AIBExtraArgs) != len(expected) {
		t.Fatalf("expected %d extra args, got %d: %v", len(expected), len(req.AIBExtraArgs), req.AIBExtraArgs)
	}
	for i, arg := range expected {
		if req.AIBExtraArgs[i] != arg {
			t.Errorf("extra arg [%d]: expected %q, got %q", i, arg, req.AIBExtraArgs[i])
		}
	}
}

func TestApplyTargetDefaults_BothArchAndExtraArgs(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"ride": {
				Architecture: archARM64,
				ExtraArgs:    []string{"--separate-partitions"},
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "ride",
		Architecture: buildapitypes.Architecture(archAMD64),
		AIBExtraArgs: []string{"--my-arg"},
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archARM64) {
		t.Errorf("expected architecture arm64, got %s", req.Architecture)
	}
	expected := []string{"--separate-partitions", "--my-arg"}
	if len(req.AIBExtraArgs) != len(expected) {
		t.Fatalf("expected %d extra args, got %d: %v", len(expected), len(req.AIBExtraArgs), req.AIBExtraArgs)
	}
	for i, arg := range expected {
		if req.AIBExtraArgs[i] != arg {
			t.Errorf("extra arg [%d]: expected %q, got %q", i, arg, req.AIBExtraArgs[i])
		}
	}
}

func TestApplyTargetDefaults_MappingWithEmptyArchDoesNotOverride(t *testing.T) {
	cmd := newCmdWithArchFlag(archAMD64, false)
	config := &buildapitypes.OperatorConfigResponse{
		TargetDefaults: map[string]buildapitypes.TargetDefaults{
			"qemu": {
				// Architecture intentionally empty
			},
		},
	}
	req := &buildapitypes.BuildRequest{
		Target:       "qemu",
		Architecture: buildapitypes.Architecture(archAMD64),
	}

	applyTargetDefaults(cmd, config, req)

	if req.Architecture != buildapitypes.Architecture(archAMD64) {
		t.Errorf("expected architecture to remain amd64 when mapping has no arch, got %s", req.Architecture)
	}
}
