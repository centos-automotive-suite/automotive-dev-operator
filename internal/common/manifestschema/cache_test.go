package manifestschema

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func withTempCacheDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	original := schemaCacheDir
	schemaCacheDir = func() (string, error) { return dir, nil }
	t.Cleanup(func() { schemaCacheDir = original })
}

func TestCacheKeyDeterminism(t *testing.T) {
	a := cacheKeyFor("sha256:abc123")
	b := cacheKeyFor("sha256:abc123")
	if a != b {
		t.Errorf("same input produced different keys: %s vs %s", a, b)
	}
	c := cacheKeyFor("sha256:def456")
	if a == c {
		t.Error("different inputs produced same key")
	}
}

const (
	testDigest   = "sha256:abc123"
	testImageRef = "quay.io/org/repo:latest"
)

func TestCacheHit(t *testing.T) {
	withTempCacheDir(t)
	data := []byte("type: object\n")
	digest := testDigest

	if err := saveCachedSchema(digest, data); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got := loadCachedSchema(digest)
	if got == nil {
		t.Fatal("expected cache hit")
	}
	if string(got) != string(data) {
		t.Errorf("got %q, want %q", got, data)
	}
}

func TestCacheMissNonexistent(t *testing.T) {
	withTempCacheDir(t)
	got := loadCachedSchema("sha256:doesnotexist")
	if got != nil {
		t.Error("expected nil for nonexistent key")
	}
}

func TestSaveCreatesCacheDir(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "deep", "nested")
	schemaCacheDir = func() (string, error) { return nested, nil }
	t.Cleanup(func() { schemaCacheDir = defaultCacheDir })

	err := saveCachedSchema("sha256:abc123", []byte("data"))
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Error("expected cache directory to be created")
	}
}

func TestCacheImmutable(t *testing.T) {
	withTempCacheDir(t)
	digest := testDigest
	data := []byte("type: object\n")

	if err := saveCachedSchema(digest, data); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	got := loadCachedSchema(digest)
	if got == nil {
		t.Fatal("expected cache hit — digest entries never expire")
	}
}

func TestDigestCacheHit(t *testing.T) {
	withTempCacheDir(t)
	saveCachedDigest(testImageRef, testDigest)

	got := loadCachedDigest(testImageRef)
	if got != testDigest {
		t.Errorf("got %q, want %q", got, testDigest)
	}
}

func TestDigestCacheMiss(t *testing.T) {
	withTempCacheDir(t)
	got := loadCachedDigest("quay.io/org/repo:nonexistent")
	if got != "" {
		t.Errorf("expected empty string for miss, got %q", got)
	}
}

func TestDigestCacheExpired(t *testing.T) {
	withTempCacheDir(t)
	saveCachedDigest(testImageRef, testDigest)

	// Backdate the file to make it expired.
	dir, _ := schemaCacheDir()
	path := filepath.Join(dir, "digest-"+cacheKeyFor(testImageRef)+".txt")
	old := time.Now().Add(-10 * time.Minute)
	_ = os.Chtimes(path, old, old)

	got := loadCachedDigest(testImageRef)
	if got != "" {
		t.Errorf("expected empty string for expired entry, got %q", got)
	}
}

func TestDigestCacheMalformed(t *testing.T) {
	withTempCacheDir(t)
	dir, _ := schemaCacheDir()
	_ = os.MkdirAll(dir, 0755)
	target := filepath.Join(dir, "digest-"+cacheKeyFor(testImageRef)+".txt")
	_ = os.WriteFile(target, []byte("garbage"), 0644)

	got := loadCachedDigest(testImageRef)
	if got != "" {
		t.Errorf("expected empty string for malformed digest, got %q", got)
	}
}

func TestDigestCacheOverwrite(t *testing.T) {
	withTempCacheDir(t)
	saveCachedDigest(testImageRef, "sha256:old")
	saveCachedDigest(testImageRef, "sha256:new")

	got := loadCachedDigest(testImageRef)
	if got != "sha256:new" {
		t.Errorf("got %q, want %q", got, "sha256:new")
	}
}
