package caibcommon

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	buildapitypes "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi"
	buildapiclient "github.com/centos-automotive-suite/automotive-dev-operator/internal/buildapi/client"
)

func TestExecuteWithReauthPreservesForbiddenResponse(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/v1/workspaces" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"image is not in the allowed images list"}`))
	}))
	defer server.Close()

	token := "valid-token"
	err := ExecuteWithReauth(server.URL, &token, false, func(client *buildapiclient.Client) error {
		_, createErr := client.CreateWorkspace(context.Background(), buildapitypes.WorkspaceRequest{Name: "test"})
		return createErr
	})

	if err == nil || !strings.Contains(err.Error(), "403 Forbidden") || !strings.Contains(err.Error(), "image is not in the allowed images list") {
		t.Fatalf("expected original forbidden response, got %v", err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("expected one request without reauthentication, got %d", got)
	}
}

// tokenCacheFileName mirrors the unexported cache file name used by the auth package.
const tokenCacheFileName = "token.json"

// makeTestJWT builds an unsigned JWT with the given issuer and lifetime.
func makeTestJWT(issuer string, lifetime time.Duration) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(map[string]any{
		"sub": "test-user",
		"iss": issuer,
		"exp": float64(time.Now().Add(lifetime).Unix()),
	})
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// isolateHome points HOME, the kubeconfig and PATH at an empty temp dir so the
// auth cache is per-test and the kubeconfig fallback cannot reach a real cluster
// or shell out to `oc`.
func isolateHome(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("KUBECONFIG", filepath.Join(tmpDir, "no-such-kubeconfig"))
	t.Setenv("PATH", "")
	t.Setenv("CAIB_TOKEN", "")
	return tmpDir
}

func writeTokenCache(t *testing.T, homeDir string, cache auth.TokenCache) {
	t.Helper()
	cacheDir := filepath.Join(homeDir, ".cache", "caib")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	data, err := json.Marshal(cache)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, tokenCacheFileName), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func readTokenCache(t *testing.T, homeDir string) auth.TokenCache {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(homeDir, ".cache", "caib", tokenCacheFileName))
	if err != nil {
		t.Fatalf("token cache not readable: %v", err)
	}
	var cache auth.TokenCache
	if err := json.Unmarshal(data, &cache); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	return cache
}

// TestExecuteWithReauth_DoesNotCacheRejectedToken verifies that a token the
// server just answered 401 to is never written to the OIDC token cache. Caching
// it would drop the refresh token from a real `caib login` and leave every later
// command sending a token the server rejects.
func TestExecuteWithReauth_DoesNotCacheRejectedToken(t *testing.T) {
	homeDir := isolateHome(t)

	// Issuer whose discovery always fails, so no browser flow can start.
	issuerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer issuerSrv.Close()

	// Build API that advertises OIDC but rejects every authenticated call.
	var requests atomic.Int32
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/config" {
			requests.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"token rejected"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"clientId": "test-client",
			"jwt": []map[string]any{
				{
					"issuer": map[string]any{"url": issuerSrv.URL},
					"claimMappings": map[string]any{
						"username": map[string]any{"claim": "preferred_username"},
					},
				},
			},
		})
	}))
	defer apiSrv.Close()

	cachedToken := makeTestJWT(issuerSrv.URL, 1*time.Hour)
	writeTokenCache(t, homeDir, auth.TokenCache{
		Token:        cachedToken,
		RefreshToken: "my-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Issuer:       issuerSrv.URL,
	})

	// A token that looks reusable (unexpired, right issuer) but that the server rejects.
	rejected := makeTestJWT(issuerSrv.URL, 2*time.Hour)
	token := rejected

	err := ExecuteWithReauth(apiSrv.URL, &token, false, func(client *buildapiclient.Client) error {
		_, listErr := client.ListBuilds(context.Background())
		return listErr
	})
	if err == nil {
		t.Fatal("expected the 401 to be surfaced, got nil")
	}
	if got := requests.Load(); got < 2 {
		t.Errorf("expected a retry after re-auth, got %d request(s)", got)
	}

	cache := readTokenCache(t, homeDir)
	if cache.Token != cachedToken {
		t.Errorf("cached token was replaced by the rejected token")
	}
	if cache.RefreshToken != "my-refresh-token" {
		t.Errorf("cached refresh token = %q, want it preserved", cache.RefreshToken)
	}
	if token == rejected {
		t.Errorf("re-auth returned the rejected token instead of the cached one")
	}
}
