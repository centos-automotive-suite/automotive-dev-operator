package buildcmd

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/buildcontract"
)

func TestPinOCIRepoImages(t *testing.T) {
	previous := pinOCIRepoImageFn
	t.Cleanup(func() { pinOCIRepoImageFn = previous })
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "pinned", true: "warning fallback"}[fail], func(t *testing.T) {
			opts := newTestDiskOpts()
			opts.Registry.AuthFile = "user-auth.json"
			opts.Registry.ContainerPush = "push.example.com/output:v1"
			h := NewHandler(opts)
			ref := "quay.io/org/rpms:v1"
			pinned := ref + "@sha256:" + strings.Repeat("a", 64)
			pinOCIRepoImageFn = func(_ context.Context, image, authFile, envRegistry string) (string, error) {
				if image != ref || authFile != opts.Registry.AuthFile || envRegistry != "push.example.com" {
					t.Fatalf("pin args = %q %q %q", image, authFile, envRegistry)
				}
				if fail {
					return image, errors.New("registry unavailable")
				}
				return pinned, nil
			}
			stderr, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = stderr.Close() }()
			original := os.Stderr
			os.Stderr = stderr
			defer func() { os.Stderr = original }()
			req := &buildcontract.BuildRequest{OCIRepoImages: []string{ref}}
			h.pinOCIRepoImages(t.Context(), req)
			warning, err := os.ReadFile(stderr.Name())
			if err != nil {
				t.Fatal(err)
			}
			want := pinned
			if fail {
				want = ref
				if !strings.Contains(string(warning), "Warning:") || !strings.Contains(string(warning), "unchanged") {
					t.Fatalf("missing warning: %s", warning)
				}
			}
			if req.OCIRepoImages[0] != want {
				t.Fatalf("submitted ref = %q, want %q", req.OCIRepoImages[0], want)
			}
		})
	}
}

func TestPinOCIRepoImagesCredentialBinding(t *testing.T) {
	previous := pinOCIRepoImageFn
	t.Cleanup(func() { pinOCIRepoImageFn = previous })
	for _, tc := range []struct {
		name, push, export, url, want string
	}{
		{name: "container export", push: "push.example.com/image:v1", export: "disk.example.com/disk:v1", url: "env.example.com", want: "push.example.com"},
		{name: "disk export", export: "disk.example.com/disk:v1", want: "disk.example.com"},
		{name: "environment URL", url: "env.example.com", want: "env.example.com"},
		{name: "unbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REGISTRY_URL", tc.url)
			opts := newTestDiskOpts()
			opts.Registry.ContainerPush, opts.Registry.ExportOCI = tc.push, tc.export
			pinOCIRepoImageFn = func(_ context.Context, ref, _, boundRegistry string) (string, error) {
				if boundRegistry != tc.want {
					t.Fatalf("credential registry = %q, want %q", boundRegistry, tc.want)
				}
				return ref, nil
			}
			req := &buildcontract.BuildRequest{OCIRepoImages: []string{"repo.example.com/rpms:v1"}}
			NewHandler(opts).pinOCIRepoImages(t.Context(), req)
		})
	}
}
