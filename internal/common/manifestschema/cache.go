package manifestschema

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const cacheSubdir = "caib/schemas"

var schemaCacheDir = defaultCacheDir

func defaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, cacheSubdir), nil
}

func cacheKeyFor(digest string) string {
	h := sha256.Sum256([]byte(digest))
	return hex.EncodeToString(h[:])
}

func loadCachedSchema(digest string) []byte {
	dir, err := schemaCacheDir()
	if err != nil {
		return nil
	}

	data, err := os.ReadFile(filepath.Join(dir, cacheKeyFor(digest)+".yml"))
	if err != nil {
		return nil
	}
	return data
}

var digestCacheTTL = 5 * time.Minute

func loadCachedDigest(imageRef string) string {
	dir, err := schemaCacheDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(dir, "digest-"+cacheKeyFor(imageRef)+".txt")
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if time.Since(info.ModTime()) > digestCacheTTL {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	d := strings.TrimSpace(string(data))
	algo, hexPart, ok := strings.Cut(d, ":")
	if !ok || algo == "" || hexPart == "" {
		return ""
	}
	return d
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func saveCachedDigest(imageRef, digest string) {
	dir, err := schemaCacheDir()
	if err != nil {
		return
	}
	_ = atomicWriteFile(filepath.Join(dir, "digest-"+cacheKeyFor(imageRef)+".txt"), []byte(digest))
}

func saveCachedSchema(digest string, data []byte) error {
	dir, err := schemaCacheDir()
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dir, cacheKeyFor(digest)+".yml"), data)
}
