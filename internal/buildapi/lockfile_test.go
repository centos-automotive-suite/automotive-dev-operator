package buildapi

import (
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestLockfileBuildRequest(t *testing.T) {
	for _, tt := range []struct {
		name, lockfile, filename string
		mode                     buildcontract.Mode
		large                    bool
		valid                    bool
	}{
		{name: "bootc", lockfile: `{"version":1}`, mode: buildcontract.ModeBootc, valid: true},
		{name: "package", lockfile: `{"version":1}`, mode: buildcontract.ModePackage, valid: true},
		{name: "invalid", lockfile: `{"version":2}`, mode: buildcontract.ModeBootc},
		{name: "disk", lockfile: `{"version":1}`, mode: buildcontract.ModeDisk},
		{name: "combined size", lockfile: `{"version":1}`, mode: buildcontract.ModeBootc, large: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := &buildcontract.BuildRequest{Name: "locked", Manifest: "name: test", ManifestFileName: tt.filename, Lockfile: tt.lockfile, Mode: tt.mode, ContainerRef: "quay.io/org/image:latest"}
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
