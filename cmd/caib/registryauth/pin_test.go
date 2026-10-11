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

func TestPinImage(t *testing.T) {
	raw, err := empty.Image.RawManifest()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := empty.Image.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, auth     string
		fallback, fail bool
	}{
		{name: "HEAD"}, {name: "GET fallback", fallback: true},
		{name: "environment credentials", auth: "env"}, {name: "auth file", auth: "file"},
		{name: "registry failure", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REGISTRY_USERNAME", "")
			t.Setenv("REGISTRY_PASSWORD", "")
			var heads, gets atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.auth != "" {
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
					heads.Add(1)
				} else {
					gets.Add(1)
				}
				if tc.fail {
					http.NotFound(w, r)
					return
				}
				if tc.fallback && r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
				w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
				w.Header().Set("Docker-Content-Digest", digest.String())
				if r.Method != http.MethodHead {
					_, _ = w.Write(raw)
				}
			}))
			t.Cleanup(server.Close)
			host := strings.TrimPrefix(server.URL, "http://")
			ref := host + "/rpms:v1"
			authFile := ""
			if tc.auth == "env" {
				t.Setenv("REGISTRY_USERNAME", "user")
				t.Setenv("REGISTRY_PASSWORD", "secret")
			}
			if tc.auth == "file" {
				content, err := json.Marshal(map[string]any{"auths": map[string]any{host: map[string]string{"username": "user", "password": "secret"}}})
				if err != nil {
					t.Fatal(err)
				}
				authFile = filepath.Join(t.TempDir(), "auth.json")
				if err := os.WriteFile(authFile, content, 0600); err != nil {
					t.Fatal(err)
				}
			}
			got, err := PinImage(t.Context(), ref, authFile)
			if tc.fail {
				if err == nil || got != ref {
					t.Fatalf("failure = %q, %v", got, err)
				}
				return
			}
			if err != nil || got != ref+"@"+digest.String() {
				t.Fatalf("pinned = %q, %v", got, err)
			}
			if heads.Load() == 0 || (gets.Load() != 0) != tc.fallback {
				t.Fatalf("requests: HEAD=%d GET=%d", heads.Load(), gets.Load())
			}
		})
	}
}

func TestPinImageAlreadyPinned(t *testing.T) {
	ref := "registry.invalid/rpms:v1@sha256:" + strings.Repeat("a", 64)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := PinImage(ctx, ref, "/missing/auth.json")
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
	got, err := PinImage(ctx, ref, "")
	if err == nil || got != ref {
		t.Fatalf("cancelled resolution = %q, %v", got, err)
	}
}
