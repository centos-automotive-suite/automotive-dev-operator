package buildcmd

import (
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/commandopts"
	"github.com/spf13/cobra"
)

// newTestDiskOpts provides independent value groups for build handler tests.
func newTestDiskOpts() Options {
	return Options{
		Connection: &commandopts.Connection{ServerURL: "https://fake-server"},
		Output:     &commandopts.Output{Timeout: 60},
		Callback:   &commandopts.Callback{},
		Build: &commandopts.Build{
			Distro: "autosd", Target: "qemu", Architecture: "amd64",
			AutomotiveImageBuilder: automotivev1alpha1.DefaultAutomotiveImageBuilderImage,
			CompressionAlgo:        "gzip",
		},
		Registry: &commandopts.Registry{},
		S3:       &commandopts.S3{},
		Flash:    &commandopts.Flash{LeaseDuration: "03:00:00"},
	}
}

func TestRunDiskRejectsLeaseAndLeaseDuration(t *testing.T) {
	opts := newTestDiskOpts()
	opts.Flash.AfterBuild = true
	opts.Registry.ExportOCI = "quay.io/org/disk:v1"
	opts.Flash.JumpstarterClient = "nonexistent"
	opts.Flash.LeaseName = "my-existing-lease"

	var capturedErr error
	opts.HandleError = func(err error) { capturedErr = err }

	h := NewHandler(opts)
	cmd := &cobra.Command{}
	cmd.Flags().String("lease-duration", "03:00:00", "")
	_ = cmd.Flags().Set("lease-duration", "01:00:00")

	h.RunDisk(cmd, []string{"quay.io/test/image:latest"})

	if capturedErr == nil {
		t.Fatal("expected mutual exclusivity error, got nil")
	}
	if !strings.Contains(capturedErr.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive error, got %q", capturedErr)
	}
}

func TestRunDiskDefaultsToInternalRegistry(t *testing.T) {
	tests := []struct {
		name                string
		exportOCI           string // --push value
		outputDir           string // --output value
		useInternalRegistry bool   // --internal-registry value
		wantInternal        bool   // expected UseInternalRegistry after validation
		wantErrContains     string // if non-empty, expect an error containing this
	}{
		{
			name:         "no flags defaults to internal registry",
			wantInternal: true,
		},
		{
			name:         "output only defaults to internal registry",
			outputDir:    "my-disk.qcow2",
			wantInternal: true,
		},
		{
			name:         "push specified keeps internal registry off",
			exportOCI:    "quay.io/org/disk:v1",
			wantInternal: false,
		},
		{
			name:         "push with output keeps internal registry off",
			exportOCI:    "quay.io/org/disk:v1",
			outputDir:    "my-disk.qcow2",
			wantInternal: false,
		},
		{
			name:                "explicit internal-registry stays on",
			useInternalRegistry: true,
			wantInternal:        true,
		},
		{
			name:                "internal-registry with push is rejected",
			useInternalRegistry: true,
			exportOCI:           "quay.io/org/disk:v1",
			wantErrContains:     "--internal-registry cannot be used with --push",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := newTestDiskOpts()
			opts.Registry.ExportOCI = tc.exportOCI
			opts.Output.Dir = tc.outputDir
			opts.Registry.UseInternalRegistry = tc.useInternalRegistry

			var capturedErr error
			opts.HandleError = func(err error) { capturedErr = err }

			h := NewHandler(opts)
			cmd := &cobra.Command{}
			h.RunDisk(cmd, []string{"quay.io/test/image:latest"})

			if tc.wantErrContains != "" {
				if capturedErr == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !strings.Contains(capturedErr.Error(), tc.wantErrContains) {
					t.Fatalf("expected error containing %q, got %q", tc.wantErrContains, capturedErr)
				}
				return
			}

			if opts.Registry.UseInternalRegistry != tc.wantInternal {
				t.Errorf("UseInternalRegistry = %v, want %v", opts.Registry.UseInternalRegistry, tc.wantInternal)
			}
		})
	}
}
