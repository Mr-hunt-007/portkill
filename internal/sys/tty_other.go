//go:build !darwin && !freebsd && !netbsd && !openbsd && !dragonfly && !linux && !windows

package sys

import "os"

// IsTerminal falls back to a character device check that excludes the null
// device.
func IsTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil || st.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	if null, err := os.Stat(os.DevNull); err == nil && os.SameFile(st, null) {
		return false
	}
	return true
}
