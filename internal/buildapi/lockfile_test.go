package buildapi

import (
	"strings"
	"testing"
)

func TestLockfileBuildRequest(t *testing.T) {
	for _, tt := range []struct {
		name, lockfile, filename string
		mode                     Mode
		large                    bool
		valid                    bool
	}{
		{name: "bootc", lockfile: `{"version":1}`, mode: ModeBootc, valid: true},
		{name: "package", lockfile: `{"version":1}`, mode: ModePackage, valid: true},
		{name: "invalid", lockfile: `{"version":2}`, mode: ModeBootc},
		{name: "disk", lockfile: `{"version":1}`, mode: ModeDisk},
		{name: "combined size", lockfile: `{"version":1}`, mode: ModeBootc, large: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &BuildRequest{Name: "locked", Manifest: "name: test", ManifestFileName: tt.filename, Lockfile: tt.lockfile, Mode: tt.mode, ContainerRef: "quay.io/org/image:latest"}
			if tt.large {
				req.Manifest = strings.Repeat("x", maxManifestSize)
			}
			err := validateBuildRequest(req)
			if (err == nil) != tt.valid {
				t.Fatalf("error = %v, valid = %v", err, tt.valid)
			}
			if tt.valid && buildAIBSpec(req, req.Manifest, req.ManifestFileName, false).Lockfile != tt.lockfile {
				t.Fatal("lockfile lost when building spec")
			}
		})
	}
}
