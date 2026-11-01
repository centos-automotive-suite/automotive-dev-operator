package workspaceagent

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestFiles(t *testing.T) (*Files, string) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "export")
	files, err := NewFiles(root, filepath.Join(dir, "file-grants.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "rpms", "repodata"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "rpms", "repodata", "repomd.xml"), []byte("<repomd/>"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "id_ed25519")
	if err := os.WriteFile(secret, []byte("private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "key")); err != nil {
		t.Fatal(err)
	}
	return files, root
}

func get(t *testing.T, server *httptest.Server, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(server.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestFilesServeExportToGrantHolders(t *testing.T) {
	files, _ := newTestFiles(t)
	server := httptest.NewServer(files.Handler())
	defer server.Close()
	grant, err := files.Grant(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	prefix := "/f/" + grant.Token

	if code, body := get(t, server, prefix+"/rpms/repodata/repomd.xml"); code != http.StatusOK || body != "<repomd/>" {
		t.Errorf("granted file = %d %q, want 200 with its contents", code, body)
	}
	for _, path := range []string{
		"/f/wrong/rpms/repodata/repomd.xml", // no grant
		prefix + "/key",                     // symlink out of the export root
		prefix + "/rpms",                    // directories are not served
		prefix + "/missing",
	} {
		if code, body := get(t, server, path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d %q, want 404", path, code, body)
		}
	}
	if err := files.Revoke(grant.Token); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(t, server, prefix+"/rpms/repodata/repomd.xml"); code != http.StatusNotFound {
		t.Errorf("revoked grant = %d, want 404", code)
	}
}

func TestFilesGrantsExpireAndSurviveRestart(t *testing.T) {
	files, root := newTestFiles(t)
	now := time.Now()
	files.now = func() time.Time { return now }
	grant, err := files.Grant(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewFiles(root, files.grantsFile)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.now = files.now
	if !reloaded.valid(grant.Token) {
		t.Error("grant was lost when the agent restarted")
	}
	data, _ := os.ReadFile(files.grantsFile)
	if bytes.Contains(data, []byte(grant.Token)) {
		t.Error("grants file holds a usable token, want only its digest")
	}
	now = now.Add(2 * time.Minute)
	if reloaded.valid(grant.Token) {
		t.Error("expired grant still opens the export directory")
	}
	if _, err := files.Grant(MaxGrantTTL + time.Second); err == nil {
		t.Error("grant longer than MaxGrantTTL was accepted")
	}
}

func TestHandlerMintsFileGrants(t *testing.T) {
	files, _ := newTestFiles(t)
	server := httptest.NewServer(newTestAgent(t).Handler("secret", files))
	defer server.Close()
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/file-grants", bytes.NewBufferString(`{"ttlSeconds":60}`))
	req.Header.Set("Authorization", "Bearer secret")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var grant GrantResponse
	if err := json.NewDecoder(resp.Body).Decode(&grant); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || !files.valid(grant.Token) {
		t.Errorf("POST /file-grants = %d %+v, want 201 with a valid token", resp.StatusCode, grant)
	}
}
