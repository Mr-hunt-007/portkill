//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package sys

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal reports whether f is a terminal. A character device check alone
// is wrong: /dev/null is a character device too.
func IsTerminal(f *os.File) bool {
	var t syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(), uintptr(syscall.TIOCGETA), uintptr(unsafe.Pointer(&t)))
	return errno == 0
}
