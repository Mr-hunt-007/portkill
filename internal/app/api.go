package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// DefaultTimeout is how long a kill waits for the port to be released after
// each signal when the caller does not say.
const DefaultTimeout = 5 * time.Second

// The functions below run the same flow as the CLI without prompts and
// without writing anything to env.Stdout. They exist for the MCP server.

// quiet returns a runner that discards human readable output and never reads
// stdin, so it is safe to use while stdout carries another protocol.
func quiet(env Env, o options) *runner {
	env.Stdin = strings.NewReader("")
	env.StdinTTY = false
	// Everything worth knowing is in the report; nothing may reach the
	// real stdout, and stderr chatter would only duplicate the report.
	env.Stdout, env.Stderr = io.Discard, io.Discard
	o.json = true
	if o.signal == "" {
		o.signal = "TERM"
	}
	if o.timeout <= 0 {
		o.timeout = DefaultTimeout
	}
	return &runner{o: o, env: env, out: io.Discard, in: bufio.NewReader(env.Stdin)}
}

// Inspect reports what is listening on ports without signalling anything.
// The report is the one `portkill --dry-run --json PORTS` prints. A discovery
// failure is returned as an error.
func Inspect(env Env, ports []int, udp bool) (Report, error) {
	if len(ports) == 0 {
		return Report{}, errors.New("no port given")
	}
	rep := quiet(env, options{ports: ports, udp: udp, dryRun: true}).collect()
	if rep.Error != "" {
		return rep, errors.New(rep.Error)
	}
	return rep, nil
}

// List returns the listeners on ports (all ports when ports is nil), as
// `portkill --list --json` prints them.
func List(env Env, ports []int, udp bool) (ListReport, error) {
	entries, err := quiet(env, options{ports: ports, udp: udp}).collectList()
	return ListReport{Listeners: entries}, err
}

// KillRequest asks for one process to be stopped.
type KillRequest struct {
	Port int
	// PID must still be listening on Port when the kill starts; nothing
	// else on the port is signalled.
	PID     int
	UDP     bool
	Signal  string        // already validated; empty means TERM
	Force   bool          // send SIGKILL if the port is still busy after Timeout
	Timeout time.Duration // zero means DefaultTimeout
}

// PIDNotListeningError means the requested PID was not listening on the
// port at call time, so nothing was signalled.
type PIDNotListeningError struct{ Msg string }

func (e *PIDNotListeningError) Error() string { return e.Msg }

// KillPID stops req.PID if, and only if, it is listening on req.Port right
// now and passes every safety check the CLI applies. It answers yes to the
// kill prompt, sends SIGKILL after the timeout only when req.Force is set,
// and verifies the port afterwards. The report has exactly one port entry.
// Errors are discovery failures and *PIDNotListeningError.
func KillPID(env Env, req KillRequest) (Report, error) {
	if req.Port < 1 || req.Port > 65535 {
		return Report{}, fmt.Errorf("port %d is not between 1 and 65535", req.Port)
	}
	if req.PID < 0 {
		return Report{}, fmt.Errorf("pid %d is not a valid process ID", req.PID)
	}
	o := options{
		ports: []int{req.Port}, udp: req.UDP, yes: true, force: req.Force,
		signal: req.Signal, timeout: req.Timeout, pinned: true, pid: req.PID,
	}
	rep := quiet(env, o).collect()
	if rep.Error != "" {
		return rep, errors.New(rep.Error)
	}
	p := rep.Ports[0]
	found := false
	for _, proc := range p.Processes {
		if proc.PID == req.PID {
			found = true
		}
	}
	if !found {
		msg := p.Message
		if p.Result == ResultNotListening {
			msg = fmt.Sprintf("%s, so PID %d was not signalled", p.Message, req.PID)
		}
		return rep, &PIDNotListeningError{Msg: msg}
	}
	return rep, nil
}
