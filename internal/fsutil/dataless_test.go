//go:build darwin

package fsutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIsDatalessReturnsFalseForRegularFile — a freshly-created local
// file has no BSD flags set, so SF_DATALESS is unset and we must
// report false. Any true here would be a false-positive that masks
// real cloud placeholders.
func TestIsDatalessReturnsFalseForRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "regular.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsDataless(path) {
		t.Error("regular file should not be reported as dataless")
	}
}

// TestIsDatalessReturnsFalseForMissingFile — a missing path must not
// panic and must not return true. (Stat error → false.)
func TestIsDatalessReturnsFalseForMissingFile(t *testing.T) {
	if IsDataless("/nonexistent/path/that/does/not/exist/wormsign-test") {
		t.Error("missing file should return false (best-effort)")
	}
}

// TestIsDatalessHandlesBrokenSymlink — Lstat-based check means a
// broken symlink should not error in a way that's observable from
// the caller. The symlink itself isn't dataless; its target doesn't
// exist. We expect false.
func TestIsDatalessHandlesBrokenSymlink(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "broken-symlink")
	if err := os.Symlink(filepath.Join(dir, "nonexistent-target"), link); err != nil {
		t.Fatal(err)
	}
	if IsDataless(link) {
		t.Error("broken symlink should not be dataless")
	}
}

// TestIsDatalessOnEmptyFile — empty regular files have no special
// flags; ensures we don't trip on zero-byte files.
func TestIsDatalessOnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty")
	f, err := os.Create(path) // #nosec G304 -- test-controlled tempdir path
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if IsDataless(path) {
		t.Error("empty file should not be dataless")
	}
}
