package buildapi

import (
	"testing"
)

func TestBuildAIBSpec(t *testing.T) {
	tests := []struct {
		name             string
		req              *BuildRequest
		manifest         string
		manifestFileName string
		inputFilesServer bool
		wantDistro       string
		wantTarget       string
		wantMode         string
		wantManifest     string
		wantFileName     string
		wantImage        string
		wantBuilderImage string
		wantInputFiles   bool
		wantContainerRef string
		wantCustomDefs   []string
		wantExtraArgs    []string
		wantRootPassword string
	}{
		{
			name: "basic build spec",
			req: &BuildRequest{
				Distro: "autosd",
				Target: "qemu",
				Mode:   ModeBootc,
			},
			manifest:         "name: test\n",
			manifestFileName: "test.aib.yml",
			wantDistro:       "autosd",
			wantTarget:       "qemu",
			wantMode:         "bootc",
			wantManifest:     "name: test\n",
			wantFileName:     "test.aib.yml",
		},
		{
			name: "with custom defs and extra args",
			req: &BuildRequest{
				Distro:       "autosd",
				Target:       "qemu",
				Mode:         ModeImage,
				CustomDefs:   []string{"FOO=bar", "BAZ=qux"},
				AIBExtraArgs: []string{"--verbose", "--no-cache"},
			},
			manifest:         "name: with-defs\n",
			manifestFileName: "defs.aib.yml",
			wantDistro:       "autosd",
			wantTarget:       "qemu",
			wantMode:         "image",
			wantManifest:     "name: with-defs\n",
			wantFileName:     "defs.aib.yml",
			wantCustomDefs:   []string{"FOO=bar", "BAZ=qux"},
			wantExtraArgs:    []string{"--verbose", "--no-cache"},
		},
		{
			name: "with container ref and builder image",
			req: &BuildRequest{
				Distro:                 "cs9",
				Target:                 "aws",
				Mode:                   ModeDisk,
				ContainerRef:           "quay.io/myorg/myimage:latest",
				AutomotiveImageBuilder: "quay.io/centos-sig-automotive/aib:v1",
				BuilderImage:           "quay.io/myorg/builder:latest",
			},
			manifest:         "name: disk-build\n",
			manifestFileName: "disk.aib.yml",
			inputFilesServer: true,
			wantDistro:       "cs9",
			wantTarget:       "aws",
			wantMode:         "disk",
			wantManifest:     "name: disk-build\n",
			wantFileName:     "disk.aib.yml",
			wantContainerRef: "quay.io/myorg/myimage:latest",
			wantImage:        "quay.io/centos-sig-automotive/aib:v1",
			wantBuilderImage: "quay.io/myorg/builder:latest",
			wantInputFiles:   true,
		},
		{
			name: "with root password",
			req: &BuildRequest{
				Distro:       "autosd",
				Target:       "qemu",
				Mode:         ModeBootc,
				RootPassword: "$6$salt$hashvalue",
			},
			manifest:         "name: root-pw\n",
			manifestFileName: "root-pw.aib.yml",
			wantDistro:       "autosd",
			wantTarget:       "qemu",
			wantMode:         "bootc",
			wantManifest:     "name: root-pw\n",
			wantFileName:     "root-pw.aib.yml",
			wantRootPassword: "$6$salt$hashvalue",
		},
		{
			name: "empty manifest filename",
			req: &BuildRequest{
				Distro: "autosd",
				Target: "qemu",
				Mode:   ModeBootc,
			},
			manifest:     "name: no-filename\n",
			wantDistro:   "autosd",
			wantTarget:   "qemu",
			wantMode:     "bootc",
			wantManifest: "name: no-filename\n",
			wantFileName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAIBSpec(tt.req, tt.manifest, tt.manifestFileName, tt.inputFilesServer)

			if got.Distro != tt.wantDistro {
				t.Errorf("Distro = %q, want %q", got.Distro, tt.wantDistro)
			}
			if got.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", got.Target, tt.wantTarget)
			}
			if got.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", got.Mode, tt.wantMode)
			}
			if got.Manifest != tt.wantManifest {
				t.Errorf("Manifest = %q, want %q", got.Manifest, tt.wantManifest)
			}
			if got.ManifestFileName != tt.wantFileName {
				t.Errorf("ManifestFileName = %q, want %q", got.ManifestFileName, tt.wantFileName)
			}
			if got.Image != tt.wantImage {
				t.Errorf("Image = %q, want %q", got.Image, tt.wantImage)
			}
			if got.BuilderImage != tt.wantBuilderImage {
				t.Errorf("BuilderImage = %q, want %q", got.BuilderImage, tt.wantBuilderImage)
			}
			if got.InputFilesServer != tt.wantInputFiles {
				t.Errorf("InputFilesServer = %v, want %v", got.InputFilesServer, tt.wantInputFiles)
			}
			if got.ContainerRef != tt.wantContainerRef {
				t.Errorf("ContainerRef = %q, want %q", got.ContainerRef, tt.wantContainerRef)
			}

			// Check custom defs
			if len(tt.wantCustomDefs) > 0 {
				if len(got.CustomDefs) != len(tt.wantCustomDefs) {
					t.Errorf("CustomDefs length = %d, want %d", len(got.CustomDefs), len(tt.wantCustomDefs))
				} else {
					for i := range got.CustomDefs {
						if got.CustomDefs[i] != tt.wantCustomDefs[i] {
							t.Errorf("CustomDefs[%d] = %q, want %q", i, got.CustomDefs[i], tt.wantCustomDefs[i])
						}
					}
				}
			}

			if got.RootPassword != tt.wantRootPassword {
				t.Errorf("RootPassword = %q, want %q", got.RootPassword, tt.wantRootPassword)
			}

			// Check extra args
			if len(tt.wantExtraArgs) > 0 {
				if len(got.AIBExtraArgs) != len(tt.wantExtraArgs) {
					t.Errorf("AIBExtraArgs length = %d, want %d", len(got.AIBExtraArgs), len(tt.wantExtraArgs))
				} else {
					for i := range got.AIBExtraArgs {
						if got.AIBExtraArgs[i] != tt.wantExtraArgs[i] {
							t.Errorf("AIBExtraArgs[%d] = %q, want %q", i, got.AIBExtraArgs[i], tt.wantExtraArgs[i])
						}
					}
				}
			}
		})
	}
}
