package auth

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// withCacheLock runs fn while holding an exclusive lock on the token cache, so
// that a read-check-write sequence cannot interleave with another caib process
// doing the same — otherwise a token adopted from an external login can land on
// top of a refresh-token session saved a moment earlier and silently downgrade
// the user to a browser login.
//
// The lock lives in a sibling file rather than the cache itself: the cache is
// replaced by rename, so holders of the old inode would end up guarding a file
// nobody else can see. flock is released when the process exits, so a caib
// killed mid-login leaves nothing behind for the next run to wait on.
func withCacheLock(cachePath string, fn func() error) error {
	if err := os.MkdirAll(filepath.Dir(cachePath), 0700); err != nil {
		return err
	}

	f, err := os.OpenFile(cachePath+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open token cache lock: %w", err)
	}
	defer func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}()

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("failed to lock token cache: %w", err)
	}
	return fn()
}
