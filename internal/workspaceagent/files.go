package workspaceagent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxGrantTTL bounds a file grant's lifetime.
const MaxGrantTTL = 48 * time.Hour

// GrantRequest is the body of POST /file-grants.
type GrantRequest struct {
	TTLSeconds int64 `json:"ttlSeconds"`
}

// GrantResponse is the body returned for a new grant.
type GrantResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
}

// Files serves the export directory to builds holding a grant: a random
// token the build API mints per build and puts in the build's URLs. Grants
// are saved as digests, so they survive an agent restart without the file
// holding usable tokens.
type Files struct {
	root       string
	grantsFile string
	now        func() time.Time

	mu     sync.Mutex
	grants map[string]time.Time // token digest -> expiry
}

// NewFiles serves root, creating it if needed, with grants kept in grantsFile.
func NewFiles(root, grantsFile string) (*Files, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	f := &Files{root: root, grantsFile: grantsFile, now: time.Now, grants: map[string]time.Time{}}
	data, err := os.ReadFile(grantsFile)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &f.grants); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Grant mints a token that opens the export directory for ttl.
func (f *Files) Grant(ttl time.Duration) (GrantResponse, error) {
	if ttl <= 0 || ttl > MaxGrantTTL {
		return GrantResponse{}, apiError(http.StatusBadRequest, "ttlSeconds must be between 1 and %d", int64(MaxGrantTTL.Seconds()))
	}
	token := rand.Text()
	expires := f.now().Add(ttl).UTC()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grants[digest(token)] = expires
	if err := f.saveLocked(); err != nil {
		delete(f.grants, digest(token))
		return GrantResponse{}, err
	}
	return GrantResponse{Token: token, ExpiresAt: expires.Format(time.RFC3339)}, nil
}

// Revoke ends a grant early. Revoking an unknown grant is not an error.
func (f *Files) Revoke(token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.grants[digest(token)]; !ok {
		return nil
	}
	delete(f.grants, digest(token))
	return f.saveLocked()
}

func (f *Files) valid(token string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	expires, ok := f.grants[digest(token)]
	return ok && f.now().Before(expires)
}

// saveLocked drops expired grants and replaces the grants file.
func (f *Files) saveLocked() error {
	now := f.now()
	for key, expires := range f.grants {
		if !now.Before(expires) {
			delete(f.grants, key)
		}
	}
	data, err := json.Marshal(f.grants)
	if err != nil {
		return err
	}
	return writeFileDurably(f.grantsFile, data)
}

// Handler serves GET and HEAD /f/{token}/{path}. Every failure, including a
// bad token, is a 404, so the server reveals nothing to a caller without one.
func (f *Files) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /f/{token}/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if !f.valid(r.PathValue("token")) {
			http.NotFound(w, r)
			return
		}
		file, info, err := f.open(r.PathValue("path"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer func() { _ = file.Close() }()
		w.Header().Set("Cache-Control", "no-store")
		http.ServeContent(w, r, info.Name(), info.ModTime(), file)
	})
	return mux
}

// open resolves name under the root, following symlinks, and refuses any
// real path outside it.
func (f *Files) open(name string) (*os.File, os.FileInfo, error) {
	root, err := filepath.EvalSymlinks(f.root)
	if err != nil {
		return nil, nil, err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(path.Clean("/"+name))))
	if err != nil {
		return nil, nil, err
	}
	if real != root && !strings.HasPrefix(real, root+string(os.PathSeparator)) {
		return nil, nil, os.ErrNotExist
	}
	file, err := os.Open(real)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, os.ErrNotExist
	}
	return file, info, nil
}
