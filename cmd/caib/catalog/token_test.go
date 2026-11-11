package catalog

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// The catalog routes require a token. Without --token or CAIB_TOKEN, catalog
// commands must find one the way other caib commands do, here in the kubeconfig.
func TestListSendsKubeconfigToken(t *testing.T) {
	resetListFlagVars()
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/catalog/images":
			gotAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"items":[]}`))
		default: // includes /v1/auth/config: no OIDC on this server
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	kubeconfig := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfig, []byte(`apiVersion: v1
kind: Config
current-context: test
contexts:
- name: test
  context: {cluster: test, user: test}
clusters:
- name: test
  cluster: {server: "https://cluster.invalid"}
users:
- name: test
  user: {token: kube-token}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", kubeconfig)
	t.Setenv("CAIB_TOKEN", "")
	cmd := newListCmd() // binding the flags resets serverURL and authToken
	serverURL = srv.URL
	t.Cleanup(func() { serverURL = "" })

	if err := runList(cmd, nil); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer kube-token" {
		t.Fatalf("Authorization = %q, want the kubeconfig token", gotAuth)
	}
}
