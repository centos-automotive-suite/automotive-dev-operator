package buildcmd

import (
	"strings"
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildcontract "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/manifestschema"
)

func TestValidateSecurityFlagsInternalRegistry(t *testing.T) {
	tests := []struct {
		name         string
		secure       bool
		reproducible bool
		internal     bool
		wantError    string
	}{
		{name: "plain internal build", internal: true},
		{name: "secure external build", secure: true},
		{name: "reproducible external build", secure: true, reproducible: true},
		{name: "secure internal build", secure: true, internal: true, wantError: "--secure cannot be used with --internal-registry"},
		{name: "reproducible internal build", secure: true, reproducible: true, internal: true, wantError: "--secure cannot be used with --internal-registry"},
		{name: "reproducible without secure", reproducible: true, wantError: "--reproducible requires --secure"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := newTestDiskOpts()
			opts.Build.SecureBuild = tc.secure
			opts.Build.Reproducible = tc.reproducible
			opts.Registry.UseInternalRegistry = tc.internal

			err := NewHandler(opts).validateSecurityFlags()
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("validateSecurityFlags() error = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("validateSecurityFlags() error = %v, want substring %q", err, tc.wantError)
			}
		})
	}
}

func TestSecureBuildCommandsRejectInternalRegistry(t *testing.T) {
	for _, tc := range []struct {
		name     string
		validate func(*Handler) error
	}{
		{name: "bootc", validate: (*Handler).validateBootcBuildFlags},
		{name: "build-dev", validate: func(h *Handler) error { return h.validateBuildDevOptions("example.aib.yml") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := newTestDiskOpts()
			opts.Build.SecureBuild = true
			opts.Registry.UseInternalRegistry = true
			err := tc.validate(NewHandler(opts))
			if err == nil || !strings.Contains(err.Error(), "--secure cannot be used with --internal-registry") {
				t.Fatalf("validation error = %v, want secure internal-registry rejection", err)
			}
		})
	}
}

func TestValidateManifestSchemaImagePriority(t *testing.T) {
	const (
		flagImage     = "quay.io/custom/aib:v1"
		configImage   = "quay.io/cluster/aib:v2"
		defaultImage  = automotivev1alpha1.DefaultAutomotiveImageBuilderImage
		dummyManifest = "name: test"
	)

	tests := []struct {
		name          string
		flagValue     string
		configImage   string
		wantImageUsed string
	}{
		{
			name:          "explicit flag takes precedence over operator config",
			flagValue:     flagImage,
			configImage:   configImage,
			wantImageUsed: flagImage,
		},
		{
			name:          "operator config used when flag is default",
			flagValue:     defaultImage,
			configImage:   configImage,
			wantImageUsed: configImage,
		},
		{
			name:          "default used when no operator config",
			flagValue:     defaultImage,
			configImage:   "",
			wantImageUsed: defaultImage,
		},
		{
			name:          "explicit flag used when no operator config",
			flagValue:     flagImage,
			configImage:   "",
			wantImageUsed: flagImage,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			orig := validateFromImageFn
			defer func() { validateFromImageFn = orig }()

			var capturedImageRef string
			validateFromImageFn = func(imageRef string, _ []byte) (manifestschema.ValidationResult, error) {
				capturedImageRef = imageRef
				return manifestschema.ValidationResult{Valid: true}, nil
			}

			aibImage := tc.flagValue
			opts := newTestDiskOpts()
			opts.Build.AutomotiveImageBuilder = aibImage

			var config *buildcontract.OperatorConfigResponse
			if tc.configImage != "" {
				config = &buildcontract.OperatorConfigResponse{
					AutomotiveImageBuilder: tc.configImage,
				}
			}

			h := NewHandler(opts)
			h.validateManifestSchema(config, []byte(dummyManifest))

			if capturedImageRef != tc.wantImageUsed {
				t.Errorf("validateManifestSchema used image %q, want %q", capturedImageRef, tc.wantImageUsed)
			}
		})
	}
}

func TestValidateBuilderCachePolicy(t *testing.T) {
	opts := newTestOpts()
	opts.Build.BuilderCachePolicy = "invalid"
	if err := NewHandler(opts).validateBootcBuildFlags(); err == nil || !strings.Contains(err.Error(), "--builder-cache-policy") {
		t.Fatalf("expected policy validation error, got %v", err)
	}
}
