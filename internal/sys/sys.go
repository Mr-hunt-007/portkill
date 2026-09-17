// Package sys is the thin boundary between portkill and the operating
// system: it runs lsof, netstat, ss, ps, tasklist, PowerShell and docker,
// reads /proc, and sends signals. All parsing is delegated to package parse.
package sys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/parse"
)

// Proc is what portkill shows about a process. Empty strings and a zero
// Start mean "unknown", never "empty".
type Proc struct {
	PID        int
	PPID       int
	Name       string
	ParentName string
	User       string
	Cmd        string
	Cwd        string
	Start      time.Time
}

// OS implements the discovery and kill operations for the running system.
type OS struct{}

const cmdTimeout = 15 * time.Second

// run executes a command and returns its stdout. A non-zero exit status is
// returned as an error together with whatever was printed, because several
// tools (lsof, ps) exit 1 while still producing useful output.
func run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cmdTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			err = fmt.Errorf("%s: %w: %s", name, err, firstLine(msg))
		} else {
			err = fmt.Errorf("%s: %w", name, err)
		}
	}
	return stdout.String(), err
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func wantSet(ports []int) map[int]bool {
	if ports == nil {
		return nil
	}
	m := make(map[int]bool, len(ports))
	for _, p := range ports {
		m[p] = true
	}
	return m
}

// Listeners returns the listening TCP sockets (or bound UDP sockets when
// proto is "udp") on the given ports, or on every port when ports is nil.
// Notes are human readable caveats about incomplete visibility.
func (OS) Listeners(proto string, ports []int) ([]parse.Socket, []string, error) {
	switch runtime.GOOS {
	case "linux":
		return listenersLinux(proto, ports)
	case "windows":
		return listenersWindows(proto, ports)
	default:
		return listenersLsof(proto, ports)
	}
}

// Details looks up process information for the given PIDs. Missing entries
// mean the process vanished or could not be inspected.
func (OS) Details(pids []int) map[int]*Proc {
	switch runtime.GOOS {
	case "linux":
		return detailsLinux(pids)
	case "windows":
		return detailsWindows(pids)
	default:
		return detailsPs(pids)
	}
}

// Probe reports whether something accepts TCP connections on the loopback
// address for port. It catches listeners whose owner is invisible to the
// current user. It cannot see listeners bound only to a non-loopback address.
func (OS) Probe(port int) bool {
	for _, host := range []string{"127.0.0.1", "::1"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// DockerPS returns `docker ps` output as "name<TAB>ports" lines.
func (OS) DockerPS() (string, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return "", errors.New("docker CLI not found")
	}
	return run("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}")
}

// Self returns this process's PID and its parent's PID.
func (OS) Self() (int, int) { return os.Getpid(), os.Getppid() }

// CurrentUser returns the login name and whether the process is privileged
// (root on Unix; always false on Windows, where access is checked by the
// kill itself).
func (OS) CurrentUser() (string, bool) {
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	return name, os.Geteuid() == 0
}

// spec renders ports for lsof: "3000,5173,8000-8010".
func lsofSpec(ports []int) string {
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	var parts []string
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", sorted[i], sorted[j]))
		} else {
			parts = append(parts, strconv.Itoa(sorted[i]))
		}
		i = j + 1
	}
	return strings.Join(parts, ",")
}

func listenersLsof(proto string, ports []int) ([]parse.Socket, []string, error) {
	if _, err := exec.LookPath("lsof"); err != nil {
		return nil, nil, errors.New("lsof not found; it is required on this OS")
	}
	sel := "-iTCP"
	if proto == "udp" {
		sel = "-iUDP"
	}
	if ports != nil {
		sel += ":" + lsofSpec(ports)
	}
	args := []string{"-nP", "-w", "+c", "0", "-F", "pcLPn", sel}
	if proto == "tcp" {
		args = append(args, "-sTCP:LISTEN")
	}
	out, err := run("lsof", args...)
	// lsof exits 1 when nothing matches; that is not an error.
	if err != nil && strings.TrimSpace(out) != "" {
		err = nil
	}
	var exitErr *exec.ExitError
	if err != nil && errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		err = nil
	}
	if err != nil {
		return nil, nil, err
	}
	socks := parse.Lsof(out, wantSet(ports))
	var notes []string
	if runtime.GOOS == "darwin" {
		// Unprivileged lsof on macOS only sees the caller's own processes.
		// netstat -anv reports the PID for everyone's sockets, so merge in
		// the ones lsof could not see.
		nout, nerr := run("netstat", "-anv", "-p", proto)
		if nerr == nil || nout != "" {
			socks = mergeSockets(socks, parse.NetstatDarwin(nout, wantSet(ports)))
		}
	}
	return socks, notes, nil
}

// mergeSockets adds sockets from extra whose (proto, host, port, pid) is not
// already present in base.
func mergeSockets(base, extra []parse.Socket) []parse.Socket {
	type key struct {
		proto, host string
		port, pid   int
	}
	seen := map[key]bool{}
	pidPort := map[[2]int]bool{}
	for _, s := range base {
		seen[key{s.Proto, s.Host, s.Port, s.PID}] = true
		pidPort[[2]int{s.PID, s.Port}] = true
	}
	for _, s := range extra {
		k := key{s.Proto, s.Host, s.Port, s.PID}
		if seen[k] {
			continue
		}
		seen[k] = true
		if s.PID != 0 && pidPort[[2]int{s.PID, s.Port}] {
			// Same process and port, different spelling of the address
			// (lsof and netstat disagree about dual-stack sockets). Skip.
			continue
		}
		base = append(base, s)
	}
	return base
}

func detailsPs(pids []int) map[int]*Proc {
	res := map[int]*Proc{}
	if len(pids) == 0 {
		return res
	}
	list := joinPIDs(pids)
	out, _ := run("ps", "-o", "pid=,ppid=,user=,etime=,comm=", "-p", list)
	rows := parse.Ps(out)
	now := time.Now()
	var parents []int
	for _, pid := range pids {
		r, ok := rows[pid]
		if !ok {
			continue
		}
		res[pid] = &Proc{
			PID: pid, PPID: r.PPID, User: r.User,
			Name:  baseName(r.Comm),
			Start: now.Add(-r.Elapsed).Truncate(time.Second),
		}
		if _, ok := rows[r.PPID]; !ok && r.PPID > 0 {
			parents = append(parents, r.PPID)
		}
	}
	if len(parents) > 0 {
		pout, _ := run("ps", "-o", "pid=,ppid=,user=,etime=,comm=", "-p", joinPIDs(parents))
		for k, v := range parse.Ps(pout) {
			rows[k] = v
		}
	}
	for _, p := range res {
		if r, ok := rows[p.PPID]; ok {
			p.ParentName = baseName(r.Comm)
		}
	}
	aout, _ := run("ps", "-ww", "-o", "pid=,args=", "-p", list)
	for pid, args := range parse.PsArgs(aout) {
		if p, ok := res[pid]; ok {
			p.Cmd = args
		}
	}
	if _, err := exec.LookPath("lsof"); err == nil {
		cout, _ := run("lsof", "-a", "-p", list, "-d", "cwd", "-Fn")
		for pid, cwd := range parse.LsofCwd(cout) {
			if p, ok := res[pid]; ok {
				p.Cwd = cwd
			}
		}
	}
	return res
}

func joinPIDs(pids []int) string {
	s := make([]string, len(pids))
	for i, p := range pids {
		s[i] = strconv.Itoa(p)
	}
	return strings.Join(s, ",")
}

func baseName(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 && i < len(p)-1 {
		return p[i+1:]
	}
	return p
}
