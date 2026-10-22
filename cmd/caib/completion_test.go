package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/auth"
	"github.com/centos-automotive-suite/automotive-dev-operator/cmd/caib/config"
	"github.com/spf13/cobra"
)

func isolateCompletion(t *testing.T) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("CAIB_SERVER", "")
	t.Setenv("CAIB_TOKEN", "")
	t.Setenv("CAIB_INSECURE", "false")
	t.Setenv("SSL_CERT_FILE", "")
	t.Setenv("REQUESTS_CA_BUNDLE", "")
}

func runCompletion(t *testing.T, args ...string) ([]string, cobra.ShellCompDirective) {
	t.Helper()
	root := newRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"__complete"}, args...))
	if err := root.Execute(); err != nil {
		t.Fatalf("completion %v: %v, stderr: %s", args, err, errOut.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var directive int
	if _, err := fmt.Sscanf(lines[len(lines)-1], ":%d", &directive); err != nil {
		t.Fatalf("invalid completion output %q", out.String())
	}
	// Cobra writes this diagnostic for __complete; anything else would appear
	// in the user's shell while pressing Tab.
	if !strings.HasPrefix(errOut.String(), "Completion ended with directive: ") || strings.Count(errOut.String(), "\n") != 1 {
		t.Fatalf("unexpected completion stderr: %q", errOut.String())
	}
	return lines[:len(lines)-1], cobra.ShellCompDirective(directive)
}

func TestStaticCompletionsDoNotContactServer(t *testing.T) {
	isolateCompletion(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("static completion requested %s", r.URL)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	t.Setenv("CAIB_SERVER", server.URL)
	for _, tc := range []struct {
		args, want []string
	}{
		{[]string{"image", "build", "--format", ""}, []string{"qcow2", "raw", "simg"}},
		{[]string{"image", "build-dev", "--mode", ""}, []string{"image", "package"}},
		{[]string{"workspace", "create", "--arch", ""}, []string{"amd64", "arm64"}},
		{[]string{"image", "build", "--compress", ""}, []string{"gzip", "xz"}},
		{[]string{"image", "build", "--builder-cache-policy", ""}, []string{"validate", "reuse"}},
		{[]string{"image", "list", "--output-format", ""}, []string{"table", "json", "yaml"}},
		{[]string{"status", "--output", ""}, []string{"table", "json", "yaml"}},
	} {
		got, directive := runCompletion(t, tc.args...)
		if !reflect.DeepEqual(got, tc.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("%v: got %v (%v), want %v", tc.args, got, directive, tc.want)
		}
	}
}

func TestRemoteCompletions(t *testing.T) {
	isolateCompletion(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer flag-token" {
			t.Errorf("unexpected completion request: %s %s, auth %q", r.Method, r.URL, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/config":
			_, _ = fmt.Fprint(w, `{"targetDefaults":{"board-b":{},"board-a":{}},"jumpstarterTargets":{"board-b":{}}}`)
		case "/v1/builds":
			_, _ = fmt.Fprint(w, `[{"name":"build-b"},{"name":"other"},{"name":"build-a"},{"name":"build-a"}]`)
		case "/v1/workspaces":
			_, _ = fmt.Fprint(w, `[{"name":"ws-b"},{"name":"ws-a"}]`)
		case "/v1/container-builds":
			_, _ = fmt.Fprint(w, `[{"name":"container-a"}]`)
		default:
			t.Errorf("completion tried unexpected endpoint %s", r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	t.Setenv("CAIB_SERVER", "http://127.0.0.1:1")
	t.Setenv("CAIB_TOKEN", "env-token")
	for _, tc := range []struct {
		args, want []string
	}{
		{[]string{"image", "build", "--target", "board"}, []string{"board-a", "board-b"}},
		{[]string{"image", "flash", "--target", "board"}, []string{"board-b"}},
		{[]string{"image", "logs", "build-"}, []string{"build-a", "build-b"}},
		{[]string{"image", "show", "build-"}, []string{"build-a", "build-b"}},
		{[]string{"catalog", "publish", "build-"}, []string{"build-a", "build-b"}},
		{[]string{"workspace", "create", "--from-build", "build-"}, []string{"build-a", "build-b"}},
		{[]string{"workspace", "shell", "ws-"}, []string{"ws-a", "ws-b"}},
		{[]string{"image", "build", "--workspace", "ws-"}, []string{"ws-a", "ws-b"}},
		{[]string{"container", "logs", "cont"}, []string{"container-a"}},
	} {
		args := append([]string{}, tc.args[:2]...)
		// Insert connection flags after the subcommand and before its arguments.
		args = append(args, "--server", server.URL, "--token", "flag-token")
		args = append(args, tc.args[2:]...)
		got, directive := runCompletion(t, args...)
		if !reflect.DeepEqual(got, tc.want) || directive != cobra.ShellCompDirectiveNoFileComp {
			t.Errorf("%v: got %v (%v), want %v", args, got, directive, tc.want)
		}
	}
	if got := requests.Load(); got != 9 {
		t.Errorf("got %d requests, want one per completion", got)
	}
}

func TestCompletionStopsAfterResourceName(t *testing.T) {
	isolateCompletion(t)
	for _, tc := range []struct {
		args []string
		want cobra.ShellCompDirective
	}{
		{[]string{"workspace", "sync", "my-workspace", ""}, cobra.ShellCompDirectiveFilterDirs},
		{[]string{"workspace", "exec", "my-workspace", "--", ""}, cobra.ShellCompDirectiveNoFileComp},
		{[]string{"image", "show", "my-build", ""}, cobra.ShellCompDirectiveNoFileComp},
	} {
		got, directive := runCompletion(t, tc.args...)
		if len(got) != 0 || directive != tc.want {
			t.Errorf("%v: got %v (%v), want no values (%v)", tc.args, got, directive, tc.want)
		}
	}
}

func TestCompletionFailuresAreQuiet(t *testing.T) {
	isolateCompletion(t)
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.URL.Path != "/v1/builds" {
					t.Errorf("completion attempted authentication: %s", r.URL)
				}
				w.WriteHeader(status)
			}))
			defer server.Close()
			t.Setenv("CAIB_SERVER", server.URL)
			got, directive := runCompletion(t, "image", "logs", "")
			if len(got) != 0 || directive != cobra.ShellCompDirectiveNoFileComp || requests.Load() != 1 {
				t.Fatalf("unexpected completion: %v (%v), %d requests", got, directive, requests.Load())
			}
		})
	}
}

func TestCompletionRequestHasDeadline(t *testing.T) {
	isolateCompletion(t)
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	t.Setenv("CAIB_SERVER", server.URL)
	start := time.Now()
	got, directive := runCompletion(t, "image", "logs", "")
	if len(got) != 0 || directive != cobra.ShellCompDirectiveNoFileComp || requests.Load() != 1 || time.Since(start) > 3*completionTimeout {
		t.Fatalf("completion did not stop promptly: %v (%v), %d requests, elapsed %s", got, directive, requests.Load(), time.Since(start))
	}
}

func TestCompletionUsesSavedCredentialsWithoutRefreshing(t *testing.T) {
	isolateCompletion(t)
	cacheDir := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "caib")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, state := range []string{"valid", "expired", "other-server"} {
		t.Run(state, func(t *testing.T) {
			expiry := time.Now().Add(time.Hour)
			wantAuth := "Bearer cached-token"
			if state == "expired" {
				expiry = time.Now().Add(-time.Hour)
			}
			if state != "valid" {
				wantAuth = ""
			}
			data, err := json.Marshal(auth.TokenCache{Token: "cached-token", RefreshToken: "must-not-be-used", ExpiresAt: expiry})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cacheDir, "token.json"), data, 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/builds" || r.Header.Get("Authorization") != wantAuth {
					t.Errorf("unexpected cached authentication: %s, %q", r.URL, r.Header.Get("Authorization"))
				}
				_, _ = fmt.Fprint(w, `[{"name":"build-a"}]`)
			}))
			defer server.Close()
			if err := config.SaveServerURL(server.URL); err != nil {
				t.Fatal(err)
			}
			if state == "other-server" {
				if err := config.SaveServerURL("https://saved.example.com"); err != nil {
					t.Fatal(err)
				}
				t.Setenv("CAIB_SERVER", server.URL)
			}
			got, _ := runCompletion(t, "image", "show", "")
			if !reflect.DeepEqual(got, []string{"build-a"}) {
				t.Fatalf("unexpected results %v", got)
			}
		})
	}
}

func TestCompletionReadsKubeconfigWithoutRunningCommands(t *testing.T) {
	isolateCompletion(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	// Both commands would record any attempted credential discovery. The exec
	// entry has all required fields so an invalid kubeconfig cannot mask a call.
	script := "#!/bin/sh\nprintf called >> \"" + marker + "\"\n"
	for _, name := range []string{"credential-plugin", "oc"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	kubeconfig := filepath.Join(dir, "config")
	t.Setenv("KUBECONFIG", kubeconfig)
	for _, token := range []string{"", "kube-token"} {
		t.Run("token="+token, func(t *testing.T) {
			data := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: test
contexts:
- name: test
  context: {cluster: test, user: test}
clusters:
- name: test
  cluster: {server: https://cluster.example.com}
users:
- name: test
  user:
    token: %q
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: %s
      interactiveMode: Never
`, token, filepath.Join(dir, "credential-plugin"))
			if err := os.WriteFile(kubeconfig, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantAuth := ""
				if token != "" {
					wantAuth = "Bearer " + token
				}
				if r.URL.Path != "/v1/builds" || r.Header.Get("Authorization") != wantAuth {
					t.Errorf("unexpected kubeconfig authentication: %s, %q", r.URL, r.Header.Get("Authorization"))
				}
				_, _ = fmt.Fprint(w, `[{"name":"build-a"}]`)
			}))
			defer server.Close()
			t.Setenv("CAIB_SERVER", server.URL)
			got, _ := runCompletion(t, "image", "show", "")
			if !reflect.DeepEqual(got, []string{"build-a"}) {
				t.Fatalf("unexpected results %v", got)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("completion invoked a credential command: %v", err)
			}
		})
	}
}
