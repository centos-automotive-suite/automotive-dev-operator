package buildcmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// newTestDiskOpts returns Options with all pointer fields initialised to
// sensible zero-values so RunDisk can dereference them safely.
func newTestDiskOpts() Options {
	var (
		serverURL            = "https://fake-server"
		manifest             string
		buildName            string
		distro               = "autosd"
		target               = "qemu"
		arch                 = "amd64"
		exportFormat         string
		mode                 string
		aib                  = "quay.io/centos-sig-automotive/automotive-image-builder:latest"
		storageClass         string
		outputDir            string
		timeout              = 60
		waitForBuild         bool
		customDefs           []string
		aibExtraArgs         []string
		followLogs           bool
		compressionAlgo      = "gzip"
		authToken            string
		containerPush        string
		buildDiskImage       bool
		diskFormat           string
		exportOCI            string
		builderImage         string
		registryAuthFile     string
		containerRef         string
		rebuildBuilder       bool
		flashAfterBuild      bool
		jumpstarterClient    string
		leaseDuration        = "03:00:00"
		leaseName            string
		useInternalRegistry  bool
		internalRegImageName string
		internalRegTag       string
		insecureSkipTLS      bool
	)
	return Options{
		ServerURL:                 &serverURL,
		Manifest:                  &manifest,
		BuildName:                 &buildName,
		Distro:                    &distro,
		Target:                    &target,
		Architecture:              &arch,
		ExportFormat:              &exportFormat,
		Mode:                      &mode,
		AutomotiveImageBuilder:    &aib,
		StorageClass:              &storageClass,
		OutputDir:                 &outputDir,
		Timeout:                   &timeout,
		WaitForBuild:              &waitForBuild,
		CustomDefs:                &customDefs,
		AIBExtraArgs:              &aibExtraArgs,
		FollowLogs:                &followLogs,
		CompressionAlgo:           &compressionAlgo,
		AuthToken:                 &authToken,
		ContainerPush:             &containerPush,
		BuildDiskImage:            &buildDiskImage,
		DiskFormat:                &diskFormat,
		ExportOCI:                 &exportOCI,
		BuilderImage:              &builderImage,
		RegistryAuthFile:          &registryAuthFile,
		ContainerRef:              &containerRef,
		RebuildBuilder:            &rebuildBuilder,
		FlashAfterBuild:           &flashAfterBuild,
		JumpstarterClient:         &jumpstarterClient,
		LeaseDuration:             &leaseDuration,
		LeaseName:                 &leaseName,
		UseInternalRegistry:       &useInternalRegistry,
		InternalRegistryImageName: &internalRegImageName,
		InternalRegistryTag:       &internalRegTag,
		InsecureSkipTLS:           &insecureSkipTLS,
	}
}

func TestRunDiskRejectsLeaseAndLeaseDuration(t *testing.T) {
	opts := newTestDiskOpts()
	*opts.FlashAfterBuild = true
	*opts.ExportOCI = "quay.io/org/disk:v1"
	*opts.JumpstarterClient = "nonexistent"
	*opts.LeaseName = "my-existing-lease"

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
			*opts.ExportOCI = tc.exportOCI
			*opts.OutputDir = tc.outputDir
			*opts.UseInternalRegistry = tc.useInternalRegistry

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

			if *opts.UseInternalRegistry != tc.wantInternal {
				t.Errorf("UseInternalRegistry = %v, want %v", *opts.UseInternalRegistry, tc.wantInternal)
			}
		})
	}
}
