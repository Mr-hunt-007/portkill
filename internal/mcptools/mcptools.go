// Package mcptools exposes portkill to AI agents as MCP tools. Every handler
// runs the same code as the CLI (package app) and returns the same JSON the
// CLI prints with --json.
package mcptools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/app"
	"github.com/Mr-hunt-007/portkill/internal/mcp"
	"github.com/Mr-hunt-007/portkill/internal/parse"
)

const (
	// MaxInspectPorts caps how many ports one portkill_inspect call may
	// expand to, since every port gets an entry in the report.
	MaxInspectPorts = 100
	// DefaultListLimit is how many listeners portkill_list returns unless
	// the caller passes limit.
	DefaultListLimit = 200
	// MaxTimeout bounds how long portkill_kill may wait per signal.
	MaxTimeout = 60 * time.Second
)

const instructions = `portkill shows which process is listening on a local TCP or UDP port (PID, name, user, parent, working directory, masked command line, uptime) and whether it is safe to stop. Use portkill_inspect when a dev server fails with "address already in use" or you need to know what owns a port, and portkill_list to see every listener. ` +
	`When the server was started with --allow-destructive, portkill_kill stops one PID you got from portkill_inspect, refusing PID 1, portkill's own parent, other users' processes and Docker's port forwarder, and then verifies the port is free.`

// New builds the MCP server. env supplies the OS boundary and clock; its
// stdin and stdout are never used. portkill_kill is only registered when
// allowDestructive is true.
func New(env app.Env, allowDestructive bool) *mcp.Server {
	h := handlers{env: env}
	tools := []mcp.Tool{
		{
			Name:  "portkill_inspect",
			Title: "Inspect ports",
			Description: `Show what is listening on specific local ports, without changing anything. Use it when a server cannot bind ("EADDRINUSE", "address already in use"), before calling portkill_kill, or to learn which project a stray process belongs to.

Returns the same JSON as ` + "`portkill --dry-run --json PORTS`" + `: {"ports": [...], "exit_code": N}. One entry per requested port with "listening" and "result":
- "dry_run": at least one process could be killed.
- "not_listening": nothing is bound to the port.
- "refused": something is listening but portkill will not kill it; each process has "refusal" saying why (PID 1, portkill's own parent, another user's process, owner not visible without sudo, Docker's port forwarder).
Each process has pid, name, ppid, parent_name, user, cmd, cwd, started, uptime_seconds, addresses and killable. Optional fields are omitted when unknown. "docker" is present when the listener is a container runtime's port forwarder: {"containers": [...], "hint": "docker stop web"}; stop the container with that hint instead of killing the process. Several PIDs on one port usually share one socket (a parent and forked workers), and all of them must exit to free it.

Limits: command lines have values of flags like --password, --token and URL passwords masked, but a secret passed as a plain positional argument can still appear. Without root, other users' processes may show pid 0 or no cwd. At most ` + fmt.Sprint(MaxInspectPorts) + ` ports per call; to search a wide range use portkill_list with ports.`,
			InputSchema: mcp.Object(map[string]any{
				"ports": mcp.StringArray(`Ports to inspect. Each item is a port ("3000"), a range ("8000-8010") or a comma list ("3000,5173"). At most ` + fmt.Sprint(MaxInspectPorts) + ` ports in total.`),
				"udp":   mcp.Boolean("Look at bound UDP sockets instead of listening TCP sockets. Default false."),
			}, "ports"),
			Annotations: mcp.ReadOnly("Inspect ports"),
			Handler:     h.inspect,
		},
		{
			Name:  "portkill_list",
			Title: "List listening ports",
			Description: `List every listening TCP port on this machine (or bound UDP socket), one entry per port and PID, sorted by port. Use it to find which ports a project's servers are using, or to find listeners in a wide range; use portkill_inspect for full details on a few ports.

Returns the same JSON as ` + "`portkill --list --json`" + `: {"listeners": [{"port", "proto", "pid", "name", "user", "addresses"}]}. pid 0 and name "?" mean the owner is not visible to the current user. The list is capped at ` + fmt.Sprint(DefaultListLimit) + ` entries by default; when it is cut, "total" gives the full count and "truncated" says so, and a larger limit returns more. An empty list means nothing is listening (on the given ports).`,
			InputSchema: mcp.Object(map[string]any{
				"ports": mcp.StringArray(`Only list these ports. Items are ports ("3000"), ranges ("8000-9000") or comma lists. Omit for all ports.`),
				"udp":   mcp.Boolean("List bound UDP sockets instead of listening TCP sockets. Default false."),
				"limit": mcp.Integer("Maximum number of listeners to return. Default " + fmt.Sprint(DefaultListLimit) + "."),
			}),
			Annotations: mcp.ReadOnly("List listening ports"),
			Handler:     h.list,
		},
	}
	if allowDestructive {
		tools = append(tools, mcp.Tool{
			Name:  "portkill_kill",
			Title: "Kill the process on a port",
			Description: `Stop one process that is listening on a port. This acts immediately, with no confirmation prompt: only call it when the user wants that process stopped. Call portkill_inspect first and pass the PID it reported.

The kill only goes ahead if that PID is still listening on that port when this call runs; otherwise nothing is signalled and the call fails, so a process that took the port in the meantime is never hit. Other processes on the same port are left alone. The same refusals as the CLI apply: PID 0 (owner not visible), PID 1, the Windows System process, portkill itself and the process that started it, other users' processes unless portkill runs as root, and Docker's port forwarder (use the docker hint instead).

It sends the signal (default TERM), waits up to timeout for the port to be released, sends KILL only if force is true, then checks the port again. Returns the same JSON as ` + "`portkill --yes --json PORT`" + ` with one port entry. "result" means:
- "freed": the port was verified free afterwards.
- "declined": the process ignored the signal and force was false; it is still running.
- "refused": nothing was signalled for safety (see "message" and the process "refusal"), or the PID exited but another process still holds the port.
- "still_listening": the process survived, or a supervisor (nodemon, systemd, launchd, pm2) restarted it on the port; "message" names the new PID.
- "error": the signal failed (see "signal_error", for example permission denied).
Each process lists "signals_sent".`,
			InputSchema: mcp.Object(map[string]any{
				"port":    mcp.Integer("The port the process is listening on (1 to 65535)."),
				"pid":     mcp.Integer("PID to stop, as reported by portkill_inspect for this port. Nothing is signalled unless this PID is listening on the port at call time."),
				"udp":     mcp.Boolean("The port is a UDP port. Default false (TCP)."),
				"signal":  mcp.String("First signal to send: TERM (default), INT, HUP, QUIT, USR1, USR2 or KILL. Windows supports TERM and KILL only."),
				"force":   mcp.Boolean("Send KILL if the port is still busy after timeout. Default false, which leaves a process that ignores the first signal running."),
				"timeout": mcp.String(`How long to wait for the port to be released after each signal, as a duration such as "5s" or "500ms". Default "5s", maximum "60s".`),
			}, "port", "pid"),
			Annotations: mcp.Destructive("Kill the process on a port"),
			Handler:     h.kill,
		})
	}
	return &mcp.Server{
		Name:         "portkill",
		Title:        "portkill",
		Version:      app.Version,
		Instructions: instructions,
		Tools:        tools,
	}
}

type handlers struct {
	env app.Env
}

func parsePorts(items []string, max int) ([]int, error) {
	ports, err := parse.Ports(items)
	if err != nil {
		return nil, err
	}
	if max > 0 && len(ports) > max {
		return nil, fmt.Errorf("the ports given expand to %d ports; at most %d per call (use portkill_list with ports to find listeners in a wide range)", len(ports), max)
	}
	return ports, nil
}

func (h handlers) inspect(ctx context.Context, raw json.RawMessage) (mcp.Result, error) {
	var args struct {
		Ports []string `json:"ports"`
		UDP   bool     `json:"udp"`
	}
	if err := mcp.Decode(raw, &args); err != nil {
		return mcp.Result{}, err
	}
	if len(args.Ports) == 0 {
		return mcp.Result{}, errors.New(`ports is required, for example ["3000"] or ["8000-8010"]`)
	}
	ports, err := parsePorts(args.Ports, MaxInspectPorts)
	if err != nil {
		return mcp.Result{}, err
	}
	rep, err := app.Inspect(h.env, ports, args.UDP)
	if err != nil {
		return mcp.Result{}, fmt.Errorf("could not discover listeners: %w", err)
	}
	return mcp.JSONResult(rep)
}

// listResult is --list --json plus truncation fields that only appear when
// the list was cut.
type listResult struct {
	Listeners []*app.ListEntry `json:"listeners"`
	Total     int              `json:"total,omitempty"`
	Truncated string           `json:"truncated,omitempty"`
}

func (h handlers) list(ctx context.Context, raw json.RawMessage) (mcp.Result, error) {
	var args struct {
		Ports []string `json:"ports"`
		UDP   bool     `json:"udp"`
		Limit *int     `json:"limit"`
	}
	if err := mcp.Decode(raw, &args); err != nil {
		return mcp.Result{}, err
	}
	limit := DefaultListLimit
	if args.Limit != nil {
		if *args.Limit < 1 {
			return mcp.Result{}, fmt.Errorf("limit must be at least 1, got %d", *args.Limit)
		}
		limit = *args.Limit
	}
	var ports []int
	if len(args.Ports) > 0 {
		var err error
		if ports, err = parsePorts(args.Ports, 0); err != nil {
			return mcp.Result{}, err
		}
	}
	rep, err := app.List(h.env, ports, args.UDP)
	if err != nil {
		return mcp.Result{}, fmt.Errorf("could not discover listeners: %w", err)
	}
	out := listResult{Listeners: rep.Listeners}
	if n := len(rep.Listeners); n > limit {
		out.Listeners = rep.Listeners[:limit]
		out.Total = n
		out.Truncated = fmt.Sprintf("showing the first %d of %d listeners; pass a larger limit, or ports to narrow the list", limit, n)
	}
	return mcp.JSONResult(out)
}

func (h handlers) kill(ctx context.Context, raw json.RawMessage) (mcp.Result, error) {
	var args struct {
		Port    *int   `json:"port"`
		PID     *int   `json:"pid"`
		UDP     bool   `json:"udp"`
		Signal  string `json:"signal"`
		Force   bool   `json:"force"`
		Timeout string `json:"timeout"`
	}
	if err := mcp.Decode(raw, &args); err != nil {
		return mcp.Result{}, err
	}
	if args.Port == nil {
		return mcp.Result{}, errors.New("port is required")
	}
	if args.PID == nil {
		return mcp.Result{}, errors.New("pid is required: call portkill_inspect for this port and pass the PID it reports")
	}
	req := app.KillRequest{Port: *args.Port, PID: *args.PID, UDP: args.UDP, Force: args.Force}
	if req.Port < 1 || req.Port > 65535 {
		return mcp.Result{}, fmt.Errorf("port %d is not between 1 and 65535", req.Port)
	}
	sig := args.Signal
	if sig == "" {
		sig = "TERM"
	}
	var err error
	if req.Signal, err = h.env.ParseSignal(sig); err != nil {
		return mcp.Result{}, err
	}
	req.Timeout = app.DefaultTimeout
	if args.Timeout != "" {
		d, err := time.ParseDuration(args.Timeout)
		if err != nil {
			return mcp.Result{}, fmt.Errorf(`timeout %q is not a duration such as "5s" or "500ms"`, args.Timeout)
		}
		if d <= 0 || d > MaxTimeout {
			return mcp.Result{}, fmt.Errorf("timeout must be greater than 0 and at most %s, got %s", MaxTimeout, d)
		}
		req.Timeout = d
	}
	if err := ctx.Err(); err != nil {
		return mcp.Result{}, err
	}
	rep, err := app.KillPID(h.env, req)
	var missing *app.PIDNotListeningError
	switch {
	case errors.As(err, &missing):
		return mcp.Result{}, fmt.Errorf("%s. Call portkill_inspect again to see what is on the port now", missing.Msg)
	case err != nil:
		return mcp.Result{}, fmt.Errorf("could not discover listeners: %w", err)
	}
	return mcp.JSONResult(rep)
}
