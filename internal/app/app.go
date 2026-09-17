// Package app implements the portkill command: argument handling, the
// discover, show, confirm, signal, verify flow, and rendering. It talks to
// the operating system only through the System interface so the whole flow
// is tested with a fake.
package app

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/parse"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

// Version is the release version.
const Version = "0.2.0"

// Exit codes.
const (
	ExitFreed        = 0
	ExitNotListening = 1
	ExitError        = 2
	ExitRefused      = 3
)

// System is the OS boundary. sys.OS implements it.
type System interface {
	Listeners(proto string, ports []int) ([]parse.Socket, []string, error)
	Details(pids []int) map[int]*sys.Proc
	Signal(pid int, sig string) error
	Probe(port int) bool
	DockerPS() (string, error)
	Self() (pid, ppid int)
	CurrentUser() (name string, privileged bool)
}

// Env carries everything Run needs from the outside world.
type Env struct {
	Sys       System
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
	StdinTTY  bool
	StdoutTTY bool
	Getenv    func(string) string
	Now       func() time.Time
	Sleep     func(time.Duration)
	GOOS      string
	Home      string
	// ParseSignal validates --signal for the current OS.
	ParseSignal func(string) (string, error)
	// ServeMCP runs the MCP server on stdio for --mcp and returns the exit
	// code. It is nil in tests that do not exercise --mcp.
	ServeMCP func(allowDestructive bool) int
}

type options struct {
	udp, list, json, dryRun, yes, force, noColor, version, help bool
	mcp, allowDestructive                                       bool
	signal                                                      string
	timeout                                                     time.Duration
	ports                                                       []int
	// pinned restricts a kill to pid (MCP only). Other processes on the
	// port are left alone, and nothing is signalled if pid is not listening.
	pinned bool
	pid    int
}

const usage = `portkill: find what is listening on a port and free it.

Usage:
  portkill [flags] PORT [PORT|RANGE ...]
  portkill --list [PORT|RANGE ...]

Examples:
  portkill 3000                 show the listener on 3000 and ask to kill it
  portkill 3000 5173 8000-8010  several ports and ranges at once
  portkill --yes 3000           kill without asking (SIGTERM, wait, verify)
  portkill --force 3000         also send SIGKILL if SIGTERM does not free it
  portkill --dry-run 8080       show what would be killed, change nothing
  portkill --udp 5353           UDP instead of TCP
  portkill --list               all listening TCP ports
  portkill --json 3000 --yes    machine readable result
  portkill --mcp                MCP server on stdio for AI agents (read-only tools)

Flags:
  -y, --yes            answer yes to the kill prompt (does not imply SIGKILL)
  -f, --force          send SIGKILL without asking if the port is still busy
                       after --timeout
      --signal NAME    first signal to send (default TERM)
      --timeout DUR    how long to wait for the port to free (default 5s)
      --dry-run        show what would happen, do not signal anything
      --udp            look at UDP sockets instead of TCP
  -l, --list           list listening ports instead of killing
      --json           print JSON to stdout
      --no-color       disable colour (NO_COLOR is also honoured)
      --mcp            run an MCP server on stdio (tools: portkill_inspect,
                       portkill_list); other flags and ports are ignored
      --allow-destructive
                       with --mcp, also offer portkill_kill, which kills
                       without a confirmation prompt
      --version        print version
  -h, --help           show this help

Exit codes:
  0  every port that had a listener was freed (or --dry-run / --list found some)
  1  nothing was listening on any given port
  2  error: discovery or signal failed, or the port is still busy afterwards
     (survived SIGKILL, or a restarted process took it again)
  3  declined, refused for safety, or needs more privilege
`

// valueFlags take an argument.
var valueFlags = map[string]bool{"signal": true, "timeout": true}

// splitArgs separates flags from positional arguments so flags may appear
// anywhere ("portkill 3000 --yes").
func splitArgs(args []string) (flags, pos []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if valueFlags[name] && !strings.Contains(a, "=") && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		pos = append(pos, a)
	}
	return flags, pos
}

func parseOptions(args []string, env Env) (options, error) {
	var o options
	fs := flag.NewFlagSet("portkill", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&o.udp, "udp", false, "")
	fs.BoolVar(&o.list, "list", false, "")
	fs.BoolVar(&o.list, "l", false, "")
	fs.BoolVar(&o.json, "json", false, "")
	fs.BoolVar(&o.dryRun, "dry-run", false, "")
	fs.BoolVar(&o.yes, "yes", false, "")
	fs.BoolVar(&o.yes, "y", false, "")
	fs.BoolVar(&o.force, "force", false, "")
	fs.BoolVar(&o.force, "f", false, "")
	fs.BoolVar(&o.noColor, "no-color", false, "")
	fs.BoolVar(&o.version, "version", false, "")
	fs.BoolVar(&o.help, "help", false, "")
	fs.BoolVar(&o.help, "h", false, "")
	fs.BoolVar(&o.mcp, "mcp", false, "")
	fs.BoolVar(&o.allowDestructive, "allow-destructive", false, "")
	fs.StringVar(&o.signal, "signal", "TERM", "")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, "")
	flags, pos := splitArgs(args)
	if err := fs.Parse(flags); err != nil {
		return o, err
	}
	if o.help || o.version {
		return o, nil
	}
	if o.allowDestructive && !o.mcp {
		return o, errors.New("--allow-destructive only applies together with --mcp")
	}
	if o.mcp {
		return o, nil
	}
	if o.timeout <= 0 {
		return o, errors.New("--timeout must be positive")
	}
	sig, err := env.ParseSignal(o.signal)
	if err != nil {
		return o, err
	}
	o.signal = sig
	if len(pos) == 0 {
		if !o.list {
			return o, errors.New("no port given (try: portkill 3000, or portkill --list)")
		}
		return o, nil
	}
	o.ports, err = parse.Ports(pos)
	return o, err
}

// Run executes portkill and returns the process exit code.
func Run(args []string, env Env) int {
	o, err := parseOptions(args, env)
	if err != nil {
		fmt.Fprintf(env.Stderr, "portkill: %v\n", err)
		fmt.Fprintln(env.Stderr, "Run 'portkill --help' for usage.")
		return ExitError
	}
	if o.help {
		fmt.Fprint(env.Stdout, usage)
		return 0
	}
	if o.version {
		fmt.Fprintf(env.Stdout, "portkill %s\n", Version)
		return 0
	}
	if o.mcp {
		if env.ServeMCP == nil {
			fmt.Fprintln(env.Stderr, "portkill: MCP server not available in this build")
			return ExitError
		}
		return env.ServeMCP(o.allowDestructive)
	}
	r := &runner{o: o, env: env}
	r.color = env.StdoutTTY && !o.noColor && !o.json && env.Getenv("NO_COLOR") == ""
	r.out = env.Stdout
	r.in = bufio.NewReader(env.Stdin)
	if o.json {
		r.out = io.Discard // human text is suppressed; prompts go to stderr
	}
	if o.list {
		return r.list()
	}
	return r.kill()
}

type runner struct {
	o     options
	env   Env
	color bool
	out   io.Writer
	in    *bufio.Reader
}

func (r *runner) proto() string {
	if r.o.udp {
		return "udp"
	}
	return "tcp"
}

func (r *runner) promptOut() io.Writer {
	if r.o.json {
		return r.env.Stderr
	}
	return r.env.Stdout
}

func (r *runner) confirm(question string) bool {
	fmt.Fprintf(r.promptOut(), "%s [y/N] ", question)
	line, _ := r.in.ReadString('\n')
	ans := strings.ToLower(strings.TrimSpace(line))
	return ans == "y" || ans == "yes"
}

// ListEntry is one row of --list --json.
type ListEntry struct {
	Port      int      `json:"port"`
	Proto     string   `json:"proto"`
	PID       int      `json:"pid"`
	Name      string   `json:"name"`
	User      string   `json:"user,omitempty"`
	Addresses []string `json:"addresses"`
}

// ListReport is the JSON document printed by --list --json.
type ListReport struct {
	Listeners []*ListEntry `json:"listeners"`
}

func (r *runner) list() int {
	entries, err := r.collectList()
	if err != nil {
		fmt.Fprintf(r.env.Stderr, "portkill: %v\n", err)
		return ExitError
	}
	if r.o.json {
		writeJSON(r.env.Stdout, ListReport{entries})
	} else if len(entries) == 0 {
		fmt.Fprintf(r.out, "No listening %s ports.\n", strings.ToUpper(r.proto()))
	} else {
		r.renderList(entries)
	}
	if len(entries) == 0 {
		return ExitNotListening
	}
	return 0
}

// collectList discovers listeners and groups sockets into one entry per
// port and PID, sorted by port then PID. The slice is never nil.
func (r *runner) collectList() ([]*ListEntry, error) {
	socks, notes, err := r.env.Sys.Listeners(r.proto(), r.o.ports)
	if err != nil {
		return nil, err
	}
	for _, n := range notes {
		fmt.Fprintf(r.env.Stderr, "portkill: %s\n", n)
	}
	pids := uniquePIDs(socks)
	details := r.env.Sys.Details(pids)
	type key struct{ port, pid int }
	idx := map[key]*ListEntry{}
	entries := []*ListEntry{}
	for _, s := range socks {
		k := key{s.Port, s.PID}
		e := idx[k]
		if e == nil {
			e = &ListEntry{Port: s.Port, Proto: s.Proto, PID: s.PID, Name: s.Name, User: s.User}
			if d := details[s.PID]; d != nil {
				if e.Name == "" {
					e.Name = d.Name
				}
				if d.User != "" {
					e.User = d.User
				}
			}
			if e.PID == 0 {
				e.Name = "?"
			}
			idx[k] = e
			entries = append(entries, e)
		}
		e.Addresses = addUnique(e.Addresses, s.Addr())
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Port != entries[j].Port {
			return entries[i].Port < entries[j].Port
		}
		return entries[i].PID < entries[j].PID
	})
	return entries, nil
}

func (r *runner) renderList(entries []*ListEntry) {
	rows := [][]string{{"PORT", "PROTO", "PID", "USER", "PROCESS", "ADDRESS"}}
	for _, e := range entries {
		pid := fmt.Sprint(e.PID)
		if e.PID == 0 {
			pid = "?"
		}
		user := e.User
		if user == "" {
			user = "?"
		}
		rows = append(rows, []string{fmt.Sprint(e.Port), e.Proto, pid, user, e.Name, strings.Join(e.Addresses, ", ")})
	}
	widths := make([]int, len(rows[0]))
	for _, row := range rows {
		for i, c := range row {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for n, row := range rows {
		var b strings.Builder
		for i, c := range row {
			if i == len(row)-1 {
				b.WriteString(c)
			} else {
				b.WriteString(c + strings.Repeat(" ", widths[i]-len(c)+2))
			}
		}
		line := strings.TrimRight(b.String(), " ")
		if n == 0 {
			line = r.paint(dim, line)
		}
		fmt.Fprintln(r.out, line)
	}
}

func uniquePIDs(socks []parse.Socket) []int {
	seen := map[int]bool{}
	var pids []int
	for _, s := range socks {
		if s.PID > 0 && !seen[s.PID] {
			seen[s.PID] = true
			pids = append(pids, s.PID)
		}
	}
	sort.Ints(pids)
	return pids
}

func addUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}
