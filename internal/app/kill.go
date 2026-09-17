package app

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/parse"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

// Result values for PortReport.Result.
const (
	ResultFreed          = "freed"
	ResultNotListening   = "not_listening"
	ResultDryRun         = "dry_run"
	ResultDeclined       = "declined"
	ResultRefused        = "refused"
	ResultStillListening = "still_listening"
	ResultError          = "error"
)

// ProcReport describes one process listening on a port.
type ProcReport struct {
	PID           int      `json:"pid"`
	Name          string   `json:"name"`
	PPID          int      `json:"ppid,omitempty"`
	ParentName    string   `json:"parent_name,omitempty"`
	User          string   `json:"user,omitempty"`
	Cmd           string   `json:"cmd,omitempty"`
	Cwd           string   `json:"cwd,omitempty"`
	Started       string   `json:"started,omitempty"`
	UptimeSeconds int64    `json:"uptime_seconds,omitempty"`
	Addresses     []string `json:"addresses"`
	Killable      bool     `json:"killable"`
	Refusal       string   `json:"refusal,omitempty"`
	Docker        *Docker  `json:"docker,omitempty"`
	Signals       []string `json:"signals_sent,omitempty"`
	SignalError   string   `json:"signal_error,omitempty"`

	start      time.Time
	noGraceful bool
}

// Docker is set when the listener is a container runtime's port forwarder.
type Docker struct {
	Containers []string `json:"containers"`
	Hint       string   `json:"hint"`
}

// PortReport is the outcome for one port.
type PortReport struct {
	Port      int           `json:"port"`
	Proto     string        `json:"proto"`
	Listening bool          `json:"listening"`
	Processes []*ProcReport `json:"processes"`
	Result    string        `json:"result"`
	Message   string        `json:"message,omitempty"`
}

func (r *runner) kill() int {
	rep := r.collect()
	if r.o.json {
		writeJSON(r.env.Stdout, rep)
	}
	return rep.ExitCode
}

// collect runs discovery and the per-port flow and returns the report that
// --json prints. Human readable text goes to r.out as it happens.
func (r *runner) collect() Report {
	proto := r.proto()
	socks, notes, err := r.env.Sys.Listeners(proto, r.o.ports)
	if err != nil {
		fmt.Fprintf(r.env.Stderr, "portkill: %v\n", err)
		return Report{Ports: []*PortReport{}, Error: err.Error(), ExitCode: ExitError}
	}
	for _, n := range notes {
		fmt.Fprintf(r.env.Stderr, "portkill: %s\n", n)
	}
	details := r.env.Sys.Details(uniquePIDs(socks))
	byPort := map[int][]parse.Socket{}
	for _, s := range socks {
		byPort[s.Port] = append(byPort[s.Port], s)
	}

	reports := []*PortReport{}
	var idle []int
	printed := 0
	for _, port := range r.o.ports {
		if len(byPort[port]) == 0 && len(r.o.ports) > 1 && !(r.proto() == "tcp" && r.env.Sys.Probe(port)) {
			// Summarised below instead of one line per port of a range.
			idle = append(idle, port)
			reports = append(reports, &PortReport{
				Port: port, Proto: proto, Processes: []*ProcReport{},
				Result:  ResultNotListening,
				Message: fmt.Sprintf("nothing is listening on %s port %d", proto, port),
			})
			continue
		}
		if printed > 0 {
			fmt.Fprintln(r.out)
		}
		printed++
		reports = append(reports, r.handlePort(port, byPort[port], details))
	}
	if len(idle) > 0 {
		if printed > 0 {
			fmt.Fprintln(r.out)
		}
		fmt.Fprintln(r.out, r.paint(dim, fmt.Sprintf("Nothing listening on %s %s %s.", proto, plural(len(idle) > 1, "port", "ports"), compactPorts(idle))))
	}
	return Report{Ports: reports, ExitCode: exitCode(reports)}
}

// Report is the JSON document printed by portkill --json (without --list).
type Report struct {
	Ports    []*PortReport `json:"ports"`
	Error    string        `json:"error,omitempty"`
	ExitCode int           `json:"exit_code"`
}

func plural(many bool, one, more string) string {
	if many {
		return more
	}
	return one
}

// compactPorts renders sorted ports as "80, 3000-3002, 8080".
func compactPorts(ports []int) string {
	var parts []string
	for i := 0; i < len(ports); {
		j := i
		for j+1 < len(ports) && ports[j+1] == ports[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ports[i], ports[j]))
		} else {
			parts = append(parts, fmt.Sprint(ports[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ", ")
}

func exitCode(reports []*PortReport) int {
	has := map[string]bool{}
	for _, p := range reports {
		has[p.Result] = true
	}
	switch {
	case has[ResultError] || has[ResultStillListening]:
		return ExitError
	case has[ResultRefused] || has[ResultDeclined]:
		return ExitRefused
	case has[ResultFreed] || has[ResultDryRun]:
		return ExitFreed
	}
	return ExitNotListening
}

// buildProcs groups sockets by PID and attaches details and safety verdicts.
func (r *runner) buildProcs(port int, socks []parse.Socket, details map[int]*sys.Proc) []*ProcReport {
	byPID := map[int]*ProcReport{}
	var procs []*ProcReport
	for _, s := range socks {
		p := byPID[s.PID]
		if p == nil {
			p = &ProcReport{PID: s.PID, Name: s.Name, User: s.User}
			if d := details[s.PID]; d != nil && s.PID > 0 {
				if d.Name != "" && (p.Name == "" || len(d.Name) > len(p.Name) && strings.HasPrefix(d.Name, p.Name)) {
					p.Name = d.Name
				}
				if p.Name == "" {
					p.Name = d.Name
				}
				p.PPID, p.ParentName, p.Cwd, p.start = d.PPID, d.ParentName, d.Cwd, d.Start
				if d.User != "" {
					p.User = d.User
				}
				p.Cmd = parse.Redact(d.Cmd)
				if !d.Start.IsZero() {
					p.Started = d.Start.UTC().Format(time.RFC3339)
					p.UptimeSeconds = int64(r.env.Now().Sub(d.Start).Seconds())
				}
			}
			byPID[s.PID] = p
			procs = append(procs, p)
		}
		p.Addresses = addUnique(p.Addresses, s.Addr())
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	for _, p := range procs {
		r.classify(port, p, details[p.PID])
	}
	return procs
}

// classify decides whether p may be killed and, if not, why.
func (r *runner) classify(port int, p *ProcReport, d *sys.Proc) {
	self, parent := r.env.Sys.Self()
	me, privileged := r.env.Sys.CurrentUser()
	switch {
	case p.PID <= 0:
		p.Name = "unknown process"
		p.Refusal = "the owning process is not visible to you; run with sudo to see and kill it"
		// On Linux docker-proxy runs as root, so an invisible owner is often
		// Docker. Only mention it when a container really publishes the port.
		if d := r.dockerHint(port); len(d.Containers) > 0 {
			p.Docker = d
		}
	case p.PID == 1:
		p.Refusal = "PID 1 is the init process; refusing to signal it"
	case r.env.GOOS == "windows" && p.PID == 4:
		p.Refusal = "PID 4 is the Windows System process (usually an http.sys URL reservation); refusing to kill it"
	case p.PID == self:
		p.Refusal = "that is portkill itself"
	case p.PID == parent:
		p.Refusal = "that is the process that started portkill (your shell, or the agent running portkill --mcp); refusing to kill it"
	case parse.DockerListener(p.Name):
		p.Refusal = "this is the container runtime's port forwarder, not your app; killing it breaks every published port"
		p.Docker = r.dockerHint(port)
	case d == nil:
		p.Refusal = "could not inspect this process (it may have just exited); run again"
	case r.env.GOOS != "windows" && !privileged && p.User != "" && me != "" && p.User != me:
		p.Refusal = fmt.Sprintf("owned by user %s, not %s; run with sudo to kill it", p.User, me)
	default:
		p.Killable = true
	}
}

func (r *runner) dockerHint(port int) *Docker {
	d := &Docker{Containers: []string{}}
	out, err := r.env.Sys.DockerPS()
	if err == nil {
		d.Containers = parse.DockerContainers(out, port, r.proto())
	}
	switch len(d.Containers) {
	case 0:
		d.Hint = "docker ps  (find the container publishing this port, then docker stop it)"
	default:
		d.Hint = "docker stop " + strings.Join(d.Containers, " ")
	}
	return d
}

func (r *runner) handlePort(port int, socks []parse.Socket, details map[int]*sys.Proc) *PortReport {
	proto := r.proto()
	rep := &PortReport{Port: port, Proto: proto, Processes: []*ProcReport{}}
	if len(socks) == 0 {
		if proto == "tcp" && r.env.Sys.Probe(port) {
			// Something accepts connections but no tool showed its owner.
			socks = []parse.Socket{{Proto: proto, Host: "127.0.0.1", Port: port}}
		} else {
			rep.Result = ResultNotListening
			rep.Message = fmt.Sprintf("nothing is listening on %s port %d", proto, port)
			fmt.Fprintf(r.out, "%s %s\n", r.paint(bold, fmt.Sprintf("Port %d (%s)", port, proto)), r.paint(dim, "nothing listening"))
			return rep
		}
	}
	rep.Listening = true
	rep.Processes = r.buildProcs(port, socks, details)
	r.renderPort(rep)

	var killable []*ProcReport
	for _, p := range rep.Processes {
		if p.Killable {
			killable = append(killable, p)
		}
	}
	if r.o.pinned {
		var target *ProcReport
		for _, p := range rep.Processes {
			if p.PID == r.o.pid {
				target = p
			}
		}
		switch {
		case target == nil:
			rep.Result = ResultRefused
			rep.Message = fmt.Sprintf("PID %d is not listening on %s port %d (it is held by %s); nothing was signalled", r.o.pid, proto, port, pidList(rep.Processes))
			return rep
		case !target.Killable:
			rep.Result = ResultRefused
			rep.Message = fmt.Sprintf("PID %d will not be killed: %s", target.PID, target.Refusal)
			return rep
		}
		killable = []*ProcReport{target}
	}
	if len(killable) == 0 {
		rep.Result = ResultRefused
		rep.Message = "no process on this port can be killed by portkill"
		return rep
	}
	if len(killable) < len(rep.Processes) {
		fmt.Fprintln(r.out, r.paint(yellow, "Note: only some processes can be killed; the port will stay busy."))
	}

	if r.o.dryRun {
		for _, p := range killable {
			fmt.Fprintf(r.out, "Would send SIG%s to PID %d (%s).\n", r.o.signal, p.PID, p.Name)
		}
		rep.Result = ResultDryRun
		return rep
	}

	if !r.o.yes {
		if !r.env.StdinTTY {
			msg := "stdin is not a terminal; refusing to kill without --yes"
			fmt.Fprintf(r.env.Stderr, "portkill: %s\n", msg)
			rep.Result, rep.Message = ResultRefused, msg
			return rep
		}
		q := "Kill process?"
		if len(killable) > 1 {
			q = fmt.Sprintf("Kill %d processes?", len(killable))
		}
		if !r.confirm(q) {
			fmt.Fprintln(r.out, "Left running.")
			rep.Result = ResultDeclined
			return rep
		}
	}

	return r.terminate(rep, killable)
}

// terminate sends the signal, waits for the port to free, escalates to
// SIGKILL when allowed, and verifies the port afterwards.
func (r *runner) terminate(rep *PortReport, killable []*ProcReport) *PortReport {
	port := rep.Port
	sig := r.o.signal
	// Time may have passed at the prompt. Only signal PIDs that are still
	// listening on this port, so a PID that exited and was reused by an
	// unrelated process is not hit.
	if socks, _, err := r.env.Sys.Listeners(rep.Proto, []int{port}); err == nil {
		still := map[int]bool{}
		for _, s := range socks {
			still[s.PID] = true
		}
		var current []*ProcReport
		for _, p := range killable {
			if still[p.PID] {
				current = append(current, p)
			} else {
				fmt.Fprintf(r.out, "PID %d is no longer listening on port %d; not signalling it.\n", p.PID, port)
			}
		}
		killable = current
	}
	alive := r.send(killable, sig)
	if len(alive) == 0 && anySignalFailed(killable) {
		rep.Result = ResultError
		rep.Message = "could not signal any process"
		return rep
	}

	remaining := r.waitFree(port, alive)
	if len(remaining) > 0 && sig != "KILL" {
		after := " after " + r.o.timeout.String()
		if remaining[0].noGraceful {
			after = ""
		}
		fmt.Fprintf(r.out, "Port %d still held by %s%s.\n", port, pidList(remaining), after)
		escalate := r.o.force
		if !escalate && r.env.StdinTTY {
			escalate = r.confirm("Send SIGKILL?")
		}
		if !escalate {
			hint := "not sending SIGKILL"
			if r.o.pinned {
				hint = "not sending SIGKILL because force is false"
			} else if !r.env.StdinTTY {
				hint = "not sending SIGKILL without --force"
			}
			fmt.Fprintln(r.out, strings.ToUpper(hint[:1])+hint[1:]+".")
			rep.Result, rep.Message = ResultDeclined, fmt.Sprintf("port %d still held after SIG%s; %s", port, sig, hint)
			return rep
		}
		for _, p := range remaining {
			p.noGraceful = false
		}
		alive = r.send(remaining, "KILL")
		remaining = r.waitFree(port, alive)
	}
	if len(remaining) > 0 {
		rep.Result = ResultStillListening
		rep.Message = fmt.Sprintf("port %d is still held by %s", port, pidList(remaining))
		fmt.Fprintln(r.out, r.paint(red, fmt.Sprintf("Port %d is still held by %s.", port, pidList(remaining))))
		return rep
	}
	return r.verify(rep, killable)
}

// send signals each process and returns the ones that were signalled and
// may still be running.
func (r *runner) send(procs []*ProcReport, sig string) []*ProcReport {
	var alive []*ProcReport
	for _, p := range procs {
		err := r.env.Sys.Signal(p.PID, sig)
		switch {
		case err == nil:
			p.Signals = append(p.Signals, sig)
			fmt.Fprintf(r.out, "Sent SIG%s to PID %d (%s).\n", sig, p.PID, p.Name)
			alive = append(alive, p)
		case err == sys.ErrNoGraceful:
			p.noGraceful = true
			fmt.Fprintf(r.out, "PID %d (%s) does not accept a graceful close request.\n", p.PID, p.Name)
			alive = append(alive, p)
		case err == sys.ErrGone:
			fmt.Fprintf(r.out, "PID %d had already exited.\n", p.PID)
		case err == sys.ErrPermission:
			p.SignalError = "permission denied; run with sudo"
			fmt.Fprintln(r.env.Stderr, r.paint(red, fmt.Sprintf("portkill: PID %d: permission denied (run with sudo)", p.PID)))
		default:
			p.SignalError = err.Error()
			fmt.Fprintf(r.env.Stderr, "portkill: PID %d: %v\n", p.PID, err)
		}
	}
	return alive
}

func anySignalFailed(procs []*ProcReport) bool {
	for _, p := range procs {
		if p.SignalError != "" {
			return true
		}
	}
	return false
}

// waitFree polls until none of procs is listening on port any more, or the
// timeout passes. It returns the processes still listening.
func (r *runner) waitFree(port int, procs []*ProcReport) []*ProcReport {
	if len(procs) == 0 {
		return nil
	}
	graceless := true
	for _, p := range procs {
		if !p.noGraceful {
			graceless = false
		}
	}
	if graceless {
		return procs
	}
	deadline := r.env.Now().Add(r.o.timeout)
	for {
		socks, _, err := r.env.Sys.Listeners(r.proto(), []int{port})
		if err == nil {
			held := map[int]bool{}
			for _, s := range socks {
				held[s.PID] = true
			}
			var still []*ProcReport
			for _, p := range procs {
				if held[p.PID] {
					still = append(still, p)
				}
			}
			if len(still) == 0 {
				return nil
			}
			if !r.env.Now().Before(deadline) {
				return still
			}
		} else if !r.env.Now().Before(deadline) {
			return procs
		}
		r.env.Sleep(100 * time.Millisecond)
	}
}

// verify checks that the port is really free after the kill.
func (r *runner) verify(rep *PortReport, killed []*ProcReport) *PortReport {
	port, proto := rep.Port, rep.Proto
	socks, _, err := r.env.Sys.Listeners(proto, []int{port})
	if err != nil {
		rep.Result = ResultError
		rep.Message = "could not re-check the port: " + err.Error()
		fmt.Fprintf(r.env.Stderr, "portkill: %s\n", rep.Message)
		return rep
	}
	if len(socks) == 0 {
		if proto == "tcp" && r.env.Sys.Probe(port) {
			rep.Result = ResultStillListening
			rep.Message = fmt.Sprintf("port %d still accepts connections, but its owner is not visible (run with sudo)", port)
			fmt.Fprintln(r.out, r.paint(red, "Port still accepts connections, but its owner is not visible (run with sudo)."))
			return rep
		}
		rep.Result = ResultFreed
		rep.Message = fmt.Sprintf("%s port %d is free", proto, port)
		fmt.Fprintln(r.out, r.paint(green, fmt.Sprintf("Port %d is free.", port)))
		return rep
	}
	original := map[int]*ProcReport{}
	for _, p := range rep.Processes {
		original[p.PID] = p
	}
	var newcomers, leftovers []int
	for _, pid := range uniquePIDs(socks) {
		if _, ok := original[pid]; ok {
			leftovers = append(leftovers, pid)
		} else {
			newcomers = append(newcomers, pid)
		}
	}
	if len(newcomers) > 0 {
		d := r.env.Sys.Details(newcomers)
		names := make([]string, len(newcomers))
		for i, pid := range newcomers {
			name := "unknown"
			if p := d[pid]; p != nil {
				name = p.Name
			}
			names[i] = fmt.Sprintf("PID %d (%s)", pid, name)
		}
		rep.Result = ResultStillListening
		rep.Message = fmt.Sprintf("port %d was taken again by %s; a supervisor may have restarted it", port, strings.Join(names, ", "))
		fmt.Fprintln(r.out, r.paint(red, fmt.Sprintf("Port %d was taken again by %s. Something (a supervisor, nodemon, launchd, systemd) may have restarted it.", port, strings.Join(names, ", "))))
		return rep
	}
	rep.Result = ResultRefused
	rep.Message = fmt.Sprintf("port %d is still held by PID %s, which portkill did not kill", port, joinInts(leftovers))
	fmt.Fprintln(r.out, r.paint(yellow, fmt.Sprintf("Killed %d, but port %d is still held by PID %s.", len(killed), port, joinInts(leftovers))))
	return rep
}

func pidList(procs []*ProcReport) string {
	ids := make([]int, len(procs))
	for i, p := range procs {
		ids[i] = p.PID
	}
	return "PID " + joinInts(ids)
}

func joinInts(ids []int) string {
	s := make([]string, len(ids))
	for i, n := range ids {
		s[i] = fmt.Sprint(n)
	}
	return strings.Join(s, ", ")
}
