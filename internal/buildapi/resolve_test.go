package buildapi

import "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"

import "testing"

func TestResolveRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*buildcontract.BuildRequest)
		valid  bool
	}{
		{"valid", func(r *buildcontract.BuildRequest) {}, true},
		{"image assembly", func(r *buildcontract.BuildRequest) { r.Mode = buildcontract.ModeImage }, false},
		{"input lock", func(r *buildcontract.BuildRequest) { r.Lockfile = `{"version":1}` }, false},
		{"restore", func(r *buildcontract.BuildRequest) { r.RestoreSourcesRef = "registry/sources:latest" }, false},
		{"flash", func(r *buildcontract.BuildRequest) { r.FlashEnabled = true }, false},
		{"secure", func(r *buildcontract.BuildRequest) { r.SecureBuild = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &buildcontract.BuildRequest{Name: "resolve-test", Manifest: "name: example\n", Mode: buildcontract.ModePackage, ResolveOnly: true}
			tc.change(req)
			if err := validateBuildRequest(req); (err == nil) != tc.valid {
				t.Fatalf("validation = %v", err)
			}
			if tc.valid && !buildAIBSpec(req, req.Manifest, "example.aib.yml", false).ResolveOnly {
				t.Fatal("resolution flag lost")
			}
		})
	}
}

func TestLockedBuildRequest(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		mode                 buildcontract.Mode
		secure, repro, valid bool
	}{
		{"secure package without lock", buildcontract.ModePackage, true, false, true},
		{"reproducible package without lock", buildcontract.ModePackage, true, true, true},
		{"secure disk unsupported", buildcontract.ModeDisk, true, false, false},
		{"ordinary disk", buildcontract.ModeDisk, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &buildcontract.BuildRequest{Name: "locked-build", Mode: tc.mode, Manifest: "name: example\n", SecureBuild: tc.secure, Reproducible: tc.repro}
			if tc.mode == buildcontract.ModeDisk {
				req.ContainerRef = "registry.example/image:latest"
			}
			if err := validateBuildRequest(req); (err == nil) != tc.valid {
				t.Fatalf("validation=%v", err)
			}
		})
	}
}
