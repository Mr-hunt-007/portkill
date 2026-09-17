package sys

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ErrGone means the process no longer exists.
var ErrGone = errors.New("process already exited")

// ErrNoGraceful means the process cannot be asked to exit politely (a
// Windows console or background process without a window); only a forced
// kill will end it.
var ErrNoGraceful = errors.New("process does not accept a graceful close request")

// ErrPermission means the caller may not signal the process.
var ErrPermission = errors.New("permission denied")

// ParseSignal normalises "term", "SIGTERM" or "15" to "TERM". Only signals
// supported on this OS are accepted.
func ParseSignal(s string) (string, error) {
	up := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "SIG")
	if n, err := strconv.Atoi(up); err == nil {
		for _, name := range signalNames() {
			if num, _ := signalByName(name); num == n {
				return name, nil
			}
		}
		return "", fmt.Errorf("unsupported signal %q (supported: %s)", s, strings.Join(signalNames(), ", "))
	}
	if _, ok := signalByName(up); ok {
		return up, nil
	}
	return "", fmt.Errorf("unsupported signal %q (supported: %s)", s, strings.Join(signalNames(), ", "))
}
