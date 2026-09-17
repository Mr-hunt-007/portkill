//go:build windows

package sys

import (
	"os"
	"syscall"
)

// IsTerminal reports whether f is a console. NUL is a character device but
// has no console mode, so it is correctly reported as not a terminal.
func IsTerminal(f *os.File) bool {
	var mode uint32
	return syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode) == nil
}
