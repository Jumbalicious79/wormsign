//go:build !darwin

package fsutil

// IsDataless is a no-op on non-darwin platforms — only macOS has the
// SF_DATALESS BSD file flag.
func IsDataless(path string) bool {
	return false
}
