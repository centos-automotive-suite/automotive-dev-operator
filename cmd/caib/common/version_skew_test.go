package caibcommon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/version"
)

// listBuildsTwice makes two requests with two clients from CreateBuildAPIClient,
// as a command can, against a Build API reporting serverVersion ("" for none),
// and returns what caib wrote to stderr.
func listBuildsTwice(t *testing.T, serverVersion string) string {
	t.Helper()
	isolateHome(t)
	originalVersion := version.Version
	t.Cleanup(func() { version.Version = originalVersion })
	version.Version = "v0.3.0"
	serverVersionCheck = new(sync.Once)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if serverVersion != "" {
			w.Header().Set(version.Header, serverVersion)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(server.Close)

	return captureStderr(func() {
		for range 2 {
			token := "token"
			client, err := CreateBuildAPIClient(server.URL, &token, false)
			if err != nil {
				t.Fatalf("CreateBuildAPIClient: %v", err)
			}
			if _, err := client.ListBuilds(context.Background()); err != nil {
				t.Fatalf("ListBuilds: %v", err)
			}
		}
	})
}

// A Build API before 0.3.0 reports no version and silently drops options it
// doesn't know, so caib says so once per command.
func TestWarnsOnceAboutABuildAPIWithoutAVersion(t *testing.T) {
	stderr := listBuildsTwice(t, "")
	if got := strings.Count(stderr, "Warning:"); got != 1 {
		t.Fatalf("expected one warning, got %d in %q", got, stderr)
	}
	if !strings.Contains(stderr, version.ReleasesURL) {
		t.Errorf("warning does not say where to get caib: %q", stderr)
	}
}

// A Build API that reports a version rejects options it doesn't know, and
// failed requests name both versions, so there is nothing to warn about up
// front, whatever its version.
func TestDoesNotWarnAboutABuildAPIWithAVersion(t *testing.T) {
	if stderr := listBuildsTwice(t, "0.2.9"); strings.Contains(stderr, "Warning:") {
		t.Errorf("unexpected warning: %q", stderr)
	}
}
