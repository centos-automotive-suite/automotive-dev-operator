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
			h := NewHandler(opts)
			ref := "quay.io/org/rpms:v1"
			pinned := ref + "@sha256:" + strings.Repeat("a", 64)
			pinOCIRepoImageFn = func(_ context.Context, image, authFile string) (string, error) {
				if image != ref || authFile != opts.Registry.AuthFile {
					t.Fatalf("pin args = %q %q", image, authFile)
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
