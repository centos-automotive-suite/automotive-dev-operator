package buildcmd

import (
	"testing"

	automotivev1alpha1 "github.com/centos-automotive-suite/automotive-dev-operator/api/v1alpha1"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/manifestschema"
)

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
			opts.AutomotiveImageBuilder = &aibImage

			var config *buildapitypes.OperatorConfigResponse
			if tc.configImage != "" {
				config = &buildapitypes.OperatorConfigResponse{
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
