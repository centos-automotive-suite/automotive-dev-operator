package buildcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	buildapi "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	"github.com/spf13/cobra"
)

func TestResolveArchitecture(t *testing.T) {
	tests := map[string]string{
		"amd64":   "amd64",
		"x86_64":  "amd64",
		"arm64":   "arm64",
		"aarch64": "arm64",
	}
	for input, want := range tests {
		got, err := resolveArchitecture(input)
		if err != nil || got != want {
			t.Fatalf("resolveArchitecture(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := resolveArchitecture("ppc64le"); err == nil {
		t.Fatal("expected unsupported architecture to fail")
	}
}

func TestDefaultLockfilePath(t *testing.T) {
	got := defaultLockfilePath(filepath.Join("tmp", "image.aib.yml"))
	want := filepath.Join("tmp", "image.aib.lock")
	if got != want {
		t.Fatalf("defaultLockfilePath() = %q, want %q", got, want)
	}
}

func TestResolveSubmitsClusterOperation(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		polls        int
		want         string
		explicitArch bool
	}{
		{"normal", 0, 1, "repository unavailable", false},
		{"transient", http.StatusServiceUnavailable, 2, "repository unavailable", false},
		{"unauthorized", http.StatusUnauthorized, 1, "401", false},
		{"explicit architecture", 0, 1, "repository unavailable", true},
		{"delayed token", 0, 2, "download resolved lockfile", false},
		{"token timeout", 0, 1, "context deadline exceeded", false},
		{"stalled request", 0, 2, "repository unavailable", false},
		{"stalled overall timeout", 0, 1, "context deadline exceeded", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", "") // Resolution must not require a local container runtime.
			manifest := filepath.Join(t.TempDir(), "example.aib.yml")
			if err := os.WriteFile(manifest, []byte("name: example\n"), 0600); err != nil {
				t.Fatal(err)
			}
			wantArch := "arm64"
			if tc.explicitArch {
				wantArch = "amd64"
			}
			submitted := false
			polls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/config" {
					if err := json.NewEncoder(w).Encode(buildapi.OperatorConfigResponse{TargetDefaults: map[string]buildapi.TargetDefaults{"qemu": {Architecture: "arm64", ExtraArgs: []string{"--define", "target_default=true"}}}}); err != nil {
						t.Error(err)
					}
					return
				}
				if r.Method == http.MethodPost && r.URL.Path == "/v1/builds" {
					assertResolveRequest(t, r, wantArch)
					submitted = true
					w.WriteHeader(http.StatusAccepted)
					if _, err := fmt.Fprint(w, `{"name":"resolve-test","phase":"Pending"}`); err != nil {
						t.Error(err)
					}
					return
				}
				polls++
				if strings.HasPrefix(tc.name, "stalled") && polls == 1 {
					<-r.Context().Done()
					return
				}
				if tc.name == "delayed token" || tc.name == "token timeout" {
					token := ""
					if tc.name == "delayed token" && polls > 1 {
						token = "registry-token"
					}
					if err := json.NewEncoder(w).Encode(buildapi.BuildResponse{Name: "resolve-test", Phase: "Completed", DiskImage: "registry.example/lock:latest", RegistryToken: token}); err != nil {
						t.Error(err)
					}
					return
				}
				if polls == 1 && tc.status != 0 {
					w.WriteHeader(tc.status)
					return
				}
				if _, err := fmt.Fprint(w, `{"name":"resolve-test","phase":"Failed","message":"repository unavailable"}`); err != nil {
					t.Error(err)
				}
			}))
			defer srv.Close()
			opts := newTestOpts()
			opts.ServerURL = new(srv.URL)
			opts.AuthToken = new("test-token")
			opts.Architecture = new("amd64")
			opts.Distro = new("autosd")
			opts.Target = new("qemu")
			opts.BuildName = new("resolve-test")
			opts.AutomotiveImageBuilder = new("quay.io/example/aib:latest")
			opts.Timeout = new(1)
			opts.TTL = new("0")
			opts.DefineFiles = new([]string{})
			opts.CustomDefs = new([]string{})
			opts.AIBExtraArgs = new([]string{"--define", "user=true"})
			cmd := &cobra.Command{}
			cmd.Flags().StringVar(opts.Architecture, "arch", "amd64", "")
			if tc.explicitArch {
				if err := cmd.Flags().Set("arch", "amd64"); err != nil {
					t.Fatal(err)
				}
			}
			ctx := context.Background()
			if strings.HasSuffix(tc.name, "timeout") {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Second)
				defer cancel()
			}
			err := NewHandler(opts).resolveLockfile(ctx, cmd, manifest)
			if strings.HasSuffix(tc.name, "timeout") && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected deadline error, got %v", err)
			}
			if !submitted || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("submitted=%v, err=%v", submitted, err)
			}
			if polls != tc.polls {
				t.Fatalf("polls=%d, want %d", polls, tc.polls)
			}

		})
	}
}

func TestDownloadResolvedLockfilePreservesExistingOutput(t *testing.T) {
	for _, content := range []string{`{"version":1}`, `{"version":2}`, "", "not json"} {
		t.Run(content, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "image.aib.lock")
			if err := os.WriteFile(output, []byte("existing"), 0600); err != nil {
				t.Fatal(err)
			}
			pull := func(ctx context.Context, ref, dest, user, token string, insecure bool, auth ...string) error {
				if ref != "registry/lock@sha256:abc" || user != "serviceaccount" || token != "token" {
					t.Fatal("download credentials or reference lost")
				}
				return os.WriteFile(dest, []byte(content), 0600)
			}
			err := downloadResolvedLockfile(context.Background(), "registry/lock@sha256:abc", "token", output, false, pull)
			valid := content == `{"version":1}`
			if (err == nil) != valid {
				t.Fatalf("unexpected validation result: %v", err)
			}
			got, err := os.ReadFile(output)
			if err != nil {
				t.Fatal(err)
			}
			want := "existing"
			if valid {
				want = content
			}
			if string(got) != want {
				t.Fatalf("output = %q, want %q", got, want)
			}
		})
	}
}

func assertResolveRequest(t *testing.T, r *http.Request, wantArch string) {
	t.Helper()
	var req buildapi.BuildRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		t.Error(err)
	}
	if !req.ResolveOnly || !req.UseInternalRegistry || req.Mode != buildapi.ModePackage || string(req.Architecture) != wantArch || req.Manifest != "name: example\n" {
		t.Errorf("unexpected resolution request: %+v", req)
	}
	if !reflect.DeepEqual(req.AIBExtraArgs, []string{"--define", "target_default=true", "--define", "user=true"}) {
		t.Errorf("unexpected args: %v", req.AIBExtraArgs)
	}
}
