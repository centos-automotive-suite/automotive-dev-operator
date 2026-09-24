package buildapi

import "testing"

func TestResolveRequest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*BuildRequest)
		valid  bool
	}{
		{"valid", func(r *BuildRequest) {}, true},
		{"image assembly", func(r *BuildRequest) { r.Mode = ModeImage }, false},
		{"input lock", func(r *BuildRequest) { r.Lockfile = `{"version":1}` }, false},
		{"restore", func(r *BuildRequest) { r.RestoreSourcesRef = "registry/sources:latest" }, false},
		{"flash", func(r *BuildRequest) { r.FlashEnabled = true }, false},
		{"secure", func(r *BuildRequest) { r.SecureBuild = true }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &BuildRequest{Name: "resolve-test", Manifest: "name: example\n", Mode: ModePackage, ResolveOnly: true}
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
		mode                 Mode
		secure, repro, valid bool
	}{
		{"secure package without lock", ModePackage, true, false, true},
		{"reproducible package without lock", ModePackage, true, true, true},
		{"secure disk unsupported", ModeDisk, true, false, false},
		{"ordinary disk", ModeDisk, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &BuildRequest{Name: "locked-build", Mode: tc.mode, Manifest: "name: example\n", SecureBuild: tc.secure, Reproducible: tc.repro}
			if tc.mode == ModeDisk {
				req.ContainerRef = "registry.example/image:latest"
			}
			if err := validateBuildRequest(req); (err == nil) != tc.valid {
				t.Fatalf("validation=%v", err)
			}
		})
	}
}
