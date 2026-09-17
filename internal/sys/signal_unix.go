//go:build !windows

package sys

import (
	"errors"
	"syscall"
)

var signals = map[string]syscall.Signal{
	"TERM": syscall.SIGTERM,
	"KILL": syscall.SIGKILL,
	"INT":  syscall.SIGINT,
	"HUP":  syscall.SIGHUP,
	"QUIT": syscall.SIGQUIT,
	"USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

func signalByName(name string) (int, bool) {
	s, ok := signals[name]
	return int(s), ok
}

func signalNames() []string {
	return []string{"TERM", "KILL", "INT", "HUP", "QUIT", "USR1", "USR2"}
}

// Signal sends the named signal ("TERM", "KILL", ...) to pid.
func (OS) Signal(pid int, name string) error {
	s, ok := signals[name]
	if !ok {
		return errors.New("unsupported signal " + name)
	}
	err := syscall.Kill(pid, s)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return ErrGone
	case errors.Is(err, syscall.EPERM):
		return ErrPermission
	}
	return err
}
