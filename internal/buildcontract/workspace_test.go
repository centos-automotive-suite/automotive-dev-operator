package buildcontract

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func syncFileVersion(t *testing.T, path string) string {
	t.Helper()
	version, err := SyncFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	return version
}

// A regular file's version is its size and modification time, as rsync's
// quick check compares them, so finding one reads nothing.
func TestSyncFileVersionChangesWithSizeAndModificationTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	at := time.Date(2020, 1, 2, 3, 4, 5, 6789, time.UTC)
	write := func(content string, modified time.Time) string {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, time.Time{}, modified); err != nil {
			t.Fatal(err)
		}
		return syncFileVersion(t, path)
	}
	original := write("abc", at)
	if version := write("xyz", at); version != original {
		t.Errorf("other content of the same size and time: %q, want %q", version, original)
	}
	if version := write("abcd", at); version == original {
		t.Error("another size kept the version")
	}
	if version := write("abc", at.Add(time.Nanosecond)); version == original {
		t.Error("a nanosecond later kept the version")
	}
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if version := syncFileVersion(t, path); version == "" {
		t.Error("an unreadable file has no version")
	}
}

// A symlink syncs as a symlink, so its version is its target, whatever is
// there.
func TestSyncFileVersionIsASymlinksTarget(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	if err := os.Symlink("a", link); err != nil {
		t.Fatal(err)
	}
	toA := syncFileVersion(t, link)
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("now there"), 0o644); err != nil {
		t.Fatal(err)
	}
	if version := syncFileVersion(t, link); version != toA {
		t.Errorf("the target appearing changed the version to %q from %q", version, toA)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b", link); err != nil {
		t.Fatal(err)
	}
	if version := syncFileVersion(t, link); version == toA {
		t.Error("another target kept the version")
	}
	if version := syncFileVersion(t, filepath.Join(dir, "a")); version == toA {
		t.Error("the file a symlink names shares its version")
	}
}

// Only regular files and symlinks sync. Anything else has no version, which
// matches nothing a client sends, and a FIFO is not opened.
func TestSyncFileVersionIsEmptyForOtherFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, fifo} {
		if version := syncFileVersion(t, path); version != "" {
			t.Errorf("%s: version = %q, want none", path, version)
		}
	}
}

func TestSyncFileVersionFailsForAMissingFile(t *testing.T) {
	if _, err := SyncFileVersion(filepath.Join(t.TempDir(), "missing")); !os.IsNotExist(err) {
		t.Errorf("err = %v, want not exist", err)
	}
}
