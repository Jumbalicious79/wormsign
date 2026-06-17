//go:build darwin

package fsutil

import "syscall"

// sfDataless is the macOS BSD file flag set on iCloud / Dropbox /
// OneDrive / Google Drive / Box / any FileProvider placeholder whose
// content is NOT on the local disk. Opening such a file for read would
// trigger a network download. We must skip them for any content-reading
// operation (grep, hash, parse).
const sfDataless = 0x40000000

// IsDataless returns true if the file at path is a cloud-storage
// placeholder with no local content. A returned error or any failure
// resolves to false (best-effort — when in doubt, treat as on-disk).
func IsDataless(path string) bool {
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return false
	}
	return st.Flags&sfDataless != 0
}
