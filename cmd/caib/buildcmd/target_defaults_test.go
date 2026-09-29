package buildcmd

import (
	"testing"

	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/spf13/cobra"
)

func newCmdWithArchFlag(archValue string, changed bool) *cobra.Command {
	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().StringP("arch", "a", "amd64", "architecture")
	if changed {
		// Simulate the user explicitly setting the flag
		if err := cmd.Flags().Set("arch", archValue); err != nil {
			panic(err)
		}
	}
	return cmd
}

func TestApplyTargetDefaults_NilConfig(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", false)
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, nil, req)

	if req.Architecture != buildcontract.Architecture("amd64") {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_EmptyTargets(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("amd64") {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_NoMatchingTarget(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"qemu": {},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("amd64") {
		t.Errorf("expected architecture to remain amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_AppliesArchFromMapping(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ebbr": {
				Architecture: "arm64",
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("arm64") {
		t.Errorf("expected architecture to be overridden to arm64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_ExplicitArchOverridesMapping(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", true) // user explicitly set --arch amd64
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ebbr": {
				Architecture: "arm64",
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("amd64") {
		t.Errorf("expected explicit --arch to override mapping, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_ExplicitArchArm64OverridesMapping(t *testing.T) {
	cmd := newCmdWithArchFlag("arm64", true) // user explicitly set --arch arm64
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ebbr": {
				Architecture: "amd64", // mapping says amd64
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ebbr",
		Architecture: buildcontract.Architecture("arm64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("arm64") {
		t.Errorf("expected explicit --arch arm64 to override mapping amd64, got %s", req.Architecture)
	}
}

func TestApplyTargetDefaults_PrependsExtraArgs(t *testing.T) {
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ride": {
				ExtraArgs: []string{"--separate-partitions"},
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ride",
		Architecture: buildcontract.Architecture("amd64"),
		AIBExtraArgs: []string{"--user-arg"},
	}

	ApplyTargetDefaults(cmd, config, req)

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
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ride": {
				ExtraArgs: []string{"--separate-partitions", "--verbose"},
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ride",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

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
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"ride": {
				Architecture: "arm64",
				ExtraArgs:    []string{"--separate-partitions"},
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "ride",
		Architecture: buildcontract.Architecture("amd64"),
		AIBExtraArgs: []string{"--my-arg"},
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("arm64") {
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
	cmd := newCmdWithArchFlag("amd64", false)
	config := &buildcontract.OperatorConfigResponse{
		TargetDefaults: map[string]buildcontract.TargetDefaults{
			"qemu": {
				// Architecture intentionally empty
			},
		},
	}
	req := &buildcontract.BuildRequest{
		Target:       "qemu",
		Architecture: buildcontract.Architecture("amd64"),
	}

	ApplyTargetDefaults(cmd, config, req)

	if req.Architecture != buildcontract.Architecture("amd64") {
		t.Errorf("expected architecture to remain amd64 when mapping has no arch, got %s", req.Architecture)
	}
}
