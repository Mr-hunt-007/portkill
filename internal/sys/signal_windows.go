//go:build windows

package sys

import (
	"errors"
	"strconv"
	"strings"
)

func signalByName(name string) (int, bool) {
	switch name {
	case "TERM":
		return 15, true
	case "KILL":
		return 9, true
	}
	return 0, false
}

func signalNames() []string { return []string{"TERM", "KILL"} }

// Signal asks taskkill to end pid: "TERM" sends a close request
// (taskkill /PID), "KILL" terminates it (taskkill /F /PID).
func (OS) Signal(pid int, name string) error {
	args := []string{"/PID", strconv.Itoa(pid)}
	switch name {
	case "TERM":
	case "KILL":
		args = append([]string{"/F"}, args...)
	default:
		return errors.New("only TERM and KILL are supported on Windows")
	}
	out, err := run("taskkill", args...)
	if err == nil {
		return nil
	}
	msg := strings.ToLower(out + " " + err.Error())
	switch {
	case strings.Contains(msg, "not found"):
		return ErrGone
	case strings.Contains(msg, "access is denied"):
		return ErrPermission
	case name == "TERM" && strings.Contains(msg, "forcefully"):
		return ErrNoGraceful
	}
	return err
}
