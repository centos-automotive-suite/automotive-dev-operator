package registryauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/v1/empty"
)

type pinImageTestCase struct {
	name, auth             string
	fallback, fail         bool
	foreignEnv, unboundEnv bool
	unrelatedFile          bool
}

type pinTestRegistry struct {
	tc          pinImageTestCase
	raw         []byte
	digest      string
	heads, gets atomic.Int32
	leaked      atomic.Bool
}

func (registry *pinTestRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	user, _, _ := r.BasicAuth()
	if r.Header.Get("Authorization") != "" && (registry.tc.auth == "" || user == "push-user") {
		registry.leaked.Store(true)
	}
	if registry.tc.foreignEnv || registry.tc.unboundEnv {
		if r.URL.Path == "/v2/" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if registry.tc.auth != "" {
		user, pass, _ := r.BasicAuth()
		if user != "user" || pass != "secret" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if r.URL.Path == "/v2/" {
		return
	}
	if r.Method == http.MethodHead {
		registry.heads.Add(1)
	} else {
		registry.gets.Add(1)
	}
	if registry.tc.fail {
		http.NotFound(w, r)
		return
	}
	if registry.tc.fallback && r.Method == http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
	w.Header().Set("Content-Length", strconv.Itoa(len(registry.raw)))
	w.Header().Set("Docker-Content-Digest", registry.digest)
	if r.Method != http.MethodHead {
		_, _ = w.Write(registry.raw)
	}
}

func TestPinImage(t *testing.T) {
	raw, err := empty.Image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := empty.Image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []pinImageTestCase{
		{name: "HEAD"}, {name: "GET fallback", fallback: true},
		{name: "environment credentials", auth: "env"}, {name: "auth file", auth: "file"},
		{name: "registry failure", fail: true},
		{name: "environment credentials for another registry", foreignEnv: true},
		{name: "unbound environment credentials", unboundEnv: true},
		{name: "auth file with foreign environment credentials", auth: "file", foreignEnv: true},
		{name: "default keychain with foreign environment credentials", auth: "keychain", foreignEnv: true},
		{name: "unrelated explicit auth file uses anonymous", unrelatedFile: true},
		{name: "unrelated explicit auth file uses bound environment", auth: "env", unrelatedFile: true},
		{name: "unrelated explicit auth file uses discovered file", auth: "discovered", unrelatedFile: true},
		{name: "unrelated explicit auth file uses default keychain", auth: "keychain", unrelatedFile: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REGISTRY_USERNAME", "")
			t.Setenv("REGISTRY_PASSWORD", "")
			t.Setenv("REGISTRY_URL", "")
			t.Setenv("REGISTRY_AUTH_FILE", "")
			t.Setenv("DOCKER_CONFIG", t.TempDir())
			registry := &pinTestRegistry{tc: tc, raw: raw, digest: digest.String()}
			server := httptest.NewServer(registry)
			t.Cleanup(server.Close)
			host := strings.TrimPrefix(server.URL, "http://")
			ref := host + "/rpms:v1"
			authFile := ""
			if tc.auth == "env" || tc.foreignEnv || tc.unboundEnv {
				t.Setenv("REGISTRY_USERNAME", "user")
				t.Setenv("REGISTRY_PASSWORD", "secret")
				if tc.auth == "env" {
					t.Setenv("REGISTRY_URL", host)
				} else if tc.foreignEnv {
					t.Setenv("REGISTRY_URL", "push.example.com")
				}
				if tc.foreignEnv || tc.unboundEnv {
					t.Setenv("REGISTRY_USERNAME", "push-user")
					t.Setenv("REGISTRY_PASSWORD", "push-secret")
				}
			}
			if tc.auth == "file" || tc.auth == "keychain" || tc.auth == "discovered" {
				authFile = filepath.Join(t.TempDir(), "auth.json")
				if tc.auth == "keychain" {
					authFile = filepath.Join(os.Getenv("DOCKER_CONFIG"), "config.json")
				}
				writePinTestAuthFile(t, authFile, host)
				if tc.auth == "discovered" {
					t.Setenv("REGISTRY_AUTH_FILE", authFile)
				}
				if tc.auth != "file" {
					authFile = ""
				}
			}
			if tc.unrelatedFile {
				authFile = filepath.Join(t.TempDir(), "push-auth.json")
				writePinTestAuthFile(t, authFile, "push.example.com")
			}
			got, err := PinImage(t.Context(), ref, authFile, os.Getenv("REGISTRY_URL"))
			if registry.leaked.Load() {
				t.Fatal("unexpected credentials sent to the registry")
			}
			if tc.fail {
				if err == nil || got != ref {
					t.Fatalf("failure = %q, %v", got, err)
				}
				return
			}
			if err != nil || got != ref+"@"+digest.String() {
				t.Fatalf("pinned = %q, %v", got, err)
			}
			if registry.heads.Load() == 0 || (registry.gets.Load() != 0) != tc.fallback {
				t.Fatalf("requests: HEAD=%d GET=%d", registry.heads.Load(), registry.gets.Load())
			}
		})
	}
}

func writePinTestAuthFile(t *testing.T, path, registry string) {
	t.Helper()
	content, err := json.Marshal(map[string]any{"auths": map[string]any{registry: map[string]string{"username": "user", "password": "secret"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPinImageInvalidAuthFile(t *testing.T) {
	t.Setenv("REGISTRY_USERNAME", "user")
	t.Setenv("REGISTRY_PASSWORD", "secret")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name, content, want string
	}{
		{name: "missing", want: "failed to read --registry-auth-file"},
		{name: "malformed", content: `{"auths":`, want: "failed to parse --registry-auth-file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			authFile := filepath.Join(t.TempDir(), "auth.json")
			if tc.content != "" {
				if err := os.WriteFile(authFile, []byte(tc.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ref := "registry.invalid/rpms:v1"
			got, err := PinImage(ctx, ref, authFile, "registry.invalid")
			if got != ref || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("invalid auth file = %q, %v", got, err)
			}
		})
	}
}

func TestPinImageUnqualified(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ref := range []string{"rpms", "rpms:v1", "org/rpms:v1", "library/rpms:latest"} {
		t.Run(ref, func(t *testing.T) {
			got, err := PinImage(ctx, ref, "/missing/auth.json", "")
			if err != nil || got != ref {
				t.Fatalf("unqualified image needs lookup: %q, %v", got, err)
			}
		})
	}
}

func TestPinImageAlreadyPinned(t *testing.T) {
	ref := "registry.invalid/rpms:v1@sha256:" + strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := PinImage(ctx, ref, "/missing/auth.json", "")
	if err != nil || got != ref {
		t.Fatalf("pinned image needs lookup: %q, %v", got, err)
	}
}

func TestPinImageCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v2/" {
			return
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	ref := strings.TrimPrefix(server.URL, "http://") + "/rpms:v1"
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	got, err := PinImage(ctx, ref, "", "")
	if err == nil || got != ref {
		t.Fatalf("cancelled resolution = %q, %v", got, err)
	}
}
