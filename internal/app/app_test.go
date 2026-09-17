package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/parse"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

// fakeSys simulates listeners and processes. Signals remove a PID's sockets
// unless the PID is marked stubborn for that signal.
type fakeSys struct {
	socks      []parse.Socket
	procs      map[int]*sys.Proc
	stubborn   map[int]bool // ignores TERM/INT/HUP, dies on KILL
	immortal   map[int]bool // survives even KILL
	respawn    map[int]int  // on death, a new PID takes over the port
	signalErr  map[int]error
	probe      map[int]bool
	docker     string
	dockerErr  error
	listErr    error
	self, ppid int
	user       string
	privileged bool
	signals    []string
}

func newFake() *fakeSys {
	return &fakeSys{
		procs:     map[int]*sys.Proc{},
		stubborn:  map[int]bool{},
		immortal:  map[int]bool{},
		respawn:   map[int]int{},
		signalErr: map[int]error{},
		probe:     map[int]bool{},
		self:      999, ppid: 998, user: "dev",
	}
}

func (f *fakeSys) add(port, pid int, name, user string, hosts ...string) {
	if len(hosts) == 0 {
		hosts = []string{"*"}
	}
	for _, h := range hosts {
		f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: h, Port: port, PID: pid, Name: name})
	}
	f.procs[pid] = &sys.Proc{
		PID: pid, PPID: 500, ParentName: "zsh", Name: name, User: user,
		Cmd: name + " server.js", Cwd: "/home/dev/code/app",
		Start: fixedNow.Add(-2*time.Hour - 13*time.Minute),
	}
}

func (f *fakeSys) Listeners(proto string, ports []int) ([]parse.Socket, []string, error) {
	if f.listErr != nil {
		return nil, nil, f.listErr
	}
	want := map[int]bool{}
	for _, p := range ports {
		want[p] = true
	}
	var out []parse.Socket
	for _, s := range f.socks {
		if s.Proto == proto && (ports == nil || want[s.Port]) {
			out = append(out, s)
		}
	}
	return out, nil, nil
}

func (f *fakeSys) Details(pids []int) map[int]*sys.Proc {
	res := map[int]*sys.Proc{}
	for _, pid := range pids {
		if p, ok := f.procs[pid]; ok {
			cp := *p
			res[pid] = &cp
		}
	}
	return res
}

func (f *fakeSys) Signal(pid int, sig string) error {
	f.signals = append(f.signals, sig+":"+itoa(pid))
	if err := f.signalErr[pid]; err != nil {
		return err
	}
	if f.immortal[pid] || (f.stubborn[pid] && sig != "KILL") {
		return nil
	}
	var kept []parse.Socket
	var ports []int
	for _, s := range f.socks {
		if s.PID == pid {
			ports = append(ports, s.Port)
			continue
		}
		kept = append(kept, s)
	}
	f.socks = kept
	if np, ok := f.respawn[pid]; ok {
		for _, p := range ports {
			f.add(p, np, "node", "dev")
		}
	}
	return nil
}

func (f *fakeSys) Probe(port int) bool         { return f.probe[port] }
func (f *fakeSys) DockerPS() (string, error)   { return f.docker, f.dockerErr }
func (f *fakeSys) Self() (int, int)            { return f.self, f.ppid }
func (f *fakeSys) CurrentUser() (string, bool) { return f.user, f.privileged }
func itoa(n int) string                        { b, _ := json.Marshal(n); return string(b) }

// parseSig mirrors the Unix signal set so these tests behave the same on
// every OS; sys.ParseSignal is tested in package sys.
func parseSig(s string) (string, error) {
	up := strings.TrimPrefix(strings.ToUpper(s), "SIG")
	switch up {
	case "TERM", "KILL", "INT", "HUP", "QUIT", "USR1", "USR2":
		return up, nil
	}
	return "", errors.New("unsupported signal " + s)
}

func (f *fakeSys) sent() string { return strings.Join(f.signals, " ") }
func (f *fakeSys) listening(port int) bool {
	s, _, _ := f.Listeners("tcp", []int{port})
	return len(s) > 0
}
func (f *fakeSys) setProbe(port int, v bool)     { f.probe[port] = v }
func (f *fakeSys) setDocker(out string, e error) { f.docker, f.dockerErr = out, e }

var fixedNow = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, f *fakeSys, stdin string, tty bool, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	now := fixedNow
	env := Env{
		Sys: f, Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		StdinTTY: tty, StdoutTTY: false,
		Getenv:      func(string) string { return "" },
		Now:         func() time.Time { return now },
		Sleep:       func(d time.Duration) { now = now.Add(d) },
		GOOS:        "linux",
		Home:        "/home/dev",
		ParseSignal: parseSig,
	}
	code := Run(args, env)
	return result{code, out.String(), errb.String()}
}

func TestShowAndDecline(t *testing.T) {
	f := newFake()
	f.add(3000, 42192, "node", "dev", "*", "::")
	r := run(t, f, "n\n", true, "3000")
	want := `Port 3000 (tcp, listening)
└── node  PID 42192  user dev  up 2h13m
    parent  zsh (PID 500)
    cwd     ~/code/app
    cmd     node server.js
    addr    *:3000, [::]:3000
Kill process? [y/N] Left running.
`
	if r.stdout != want {
		t.Errorf("stdout:\n%s\nwant:\n%s", r.stdout, want)
	}
	if r.code != ExitRefused || f.sent() != "" || !f.listening(3000) {
		t.Errorf("code=%d sent=%q", r.code, f.sent())
	}
}

func TestEmptyAnswerIsNo(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	if r := run(t, f, "\n", true, "3000"); r.code != ExitRefused || f.sent() != "" {
		t.Errorf("code=%d sent=%q", r.code, f.sent())
	}
	if r := run(t, f, "", true, "3000"); r.code != ExitRefused || f.sent() != "" {
		t.Errorf("EOF: code=%d sent=%q", r.code, f.sent())
	}
}

func TestConfirmKill(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	r := run(t, f, "y\n", true, "3000")
	if r.code != ExitFreed || f.sent() != "TERM:10" {
		t.Fatalf("code=%d sent=%q out=%s", r.code, f.sent(), r.stdout)
	}
	if !strings.Contains(r.stdout, "Sent SIGTERM to PID 10 (node).\nPort 3000 is free.\n") {
		t.Errorf("stdout = %s", r.stdout)
	}
}

func TestNonTTYRefusesWithoutYes(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	r := run(t, f, "y\n", false, "3000")
	if r.code != ExitRefused || f.sent() != "" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if !strings.Contains(r.stderr, "not a terminal") {
		t.Errorf("stderr = %q", r.stderr)
	}
	r = run(t, f, "", false, "--yes", "3000")
	if r.code != ExitFreed || f.sent() != "TERM:10" {
		t.Errorf("--yes: code=%d sent=%q", r.code, f.sent())
	}
}

func TestNothingListening(t *testing.T) {
	f := newFake()
	r := run(t, f, "", false, "3000")
	if r.code != ExitNotListening || r.stdout != "Port 3000 (tcp) nothing listening\n" {
		t.Errorf("code=%d out=%q", r.code, r.stdout)
	}
}

func TestInvisibleOwner(t *testing.T) {
	f := newFake()
	f.setProbe(80, true)
	r := run(t, f, "", false, "--yes", "80")
	if r.code != ExitRefused || f.sent() != "" || !strings.Contains(r.stdout, "run with sudo") {
		t.Errorf("code=%d sent=%q out=%s", r.code, f.sent(), r.stdout)
	}
}

func TestSafetyRefusals(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(f *fakeSys)
		wantMsg string
	}{
		{"pid1", func(f *fakeSys) { f.add(8021, 1, "launchd", "root") }, "PID 1 is the init process"},
		{"self", func(f *fakeSys) { f.add(8021, 999, "portkill", "dev") }, "portkill itself"},
		{"parent shell", func(f *fakeSys) { f.add(8021, 998, "python3", "dev") }, "process that started portkill"},
		{"other user", func(f *fakeSys) { f.add(8021, 70, "nginx", "root") }, "owned by user root, not dev; run with sudo"},
		{"unknown owner", func(f *fakeSys) {
			f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: "*", Port: 8021})
		}, "not visible to you; run with sudo"},
		{"vanished", func(f *fakeSys) {
			f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: "*", Port: 8021, PID: 71, Name: "x"})
		}, "could not inspect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFake()
			tt.setup(f)
			r := run(t, f, "", false, "--yes", "--force", "8021")
			if r.code != ExitRefused || f.sent() != "" {
				t.Errorf("code=%d sent=%q", r.code, f.sent())
			}
			if !strings.Contains(r.stdout, tt.wantMsg) {
				t.Errorf("stdout missing %q:\n%s", tt.wantMsg, r.stdout)
			}
		})
	}
}

func TestRootMayKillOtherUsers(t *testing.T) {
	f := newFake()
	f.privileged = true
	f.add(80, 70, "nginx", "www-data")
	if r := run(t, f, "", false, "--yes", "80"); r.code != ExitFreed || f.sent() != "TERM:70" {
		t.Errorf("code=%d sent=%q", r.code, f.sent())
	}
}

func TestWindowsSystemPID(t *testing.T) {
	f := newFake()
	f.add(80, 4, "System", "")
	var out bytes.Buffer
	env := Env{Sys: f, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out,
		Getenv: func(string) string { return "" }, Now: func() time.Time { return fixedNow },
		Sleep: func(time.Duration) {}, GOOS: "windows", ParseSignal: parseSig}
	if code := Run([]string{"--yes", "80"}, env); code != ExitRefused || f.sent() != "" {
		t.Errorf("code=%d sent=%q", code, f.sent())
	}
	if !strings.Contains(out.String(), "Windows System process") {
		t.Errorf("out = %s", out.String())
	}
}

func TestDockerHint(t *testing.T) {
	f := newFake()
	f.add(8080, 300, "com.docker.backend", "dev")
	f.setDocker("web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\ndb\t127.0.0.1:5432->5432/tcp\n", nil)
	r := run(t, f, "y\n", true, "8080")
	if r.code != ExitRefused || f.sent() != "" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if !strings.Contains(r.stdout, "Stop the container instead:\n       docker stop web\n") || strings.Contains(r.stdout, "Kill process?") {
		t.Errorf("stdout:\n%s", r.stdout)
	}

	f2 := newFake()
	f2.add(8080, 301, "docker-proxy", "dev")
	f2.setDocker("", errors.New("docker CLI not found"))
	r = run(t, f2, "", false, "--json", "8080")
	var got Report
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatal(err)
	}
	d := got.Ports[0].Processes[0].Docker
	if d == nil || len(d.Containers) != 0 || !strings.HasPrefix(d.Hint, "docker ps") {
		t.Errorf("docker = %+v", d)
	}
}

func TestInvisibleOwnerPublishedByDocker(t *testing.T) {
	f := newFake()
	f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: "*", Port: 5432})
	f.setDocker("db\t0.0.0.0:5432->5432/tcp\n", nil)
	r := run(t, f, "", false, "--yes", "5432")
	if r.code != ExitRefused || !strings.Contains(r.stdout, "docker stop db") {
		t.Errorf("code=%d out=%s", r.code, r.stdout)
	}
	f.setDocker("other\t0.0.0.0:80->80/tcp\n", nil)
	if r := run(t, f, "", false, "--yes", "5432"); strings.Contains(r.stdout, "docker") {
		t.Errorf("unrelated container mentioned: %s", r.stdout)
	}
}

func TestMultiplePIDsDeduped(t *testing.T) {
	f := newFake()
	f.add(3000, 20, "node", "dev", "0.0.0.0", "::")
	f.add(3000, 21, "node", "dev", "0.0.0.0", "::")
	f.add(3000, 20, "node", "dev", "0.0.0.0") // duplicate row from a second source
	r := run(t, f, "", false, "--yes", "3000")
	if r.code != ExitFreed || f.sent() != "TERM:20 TERM:21" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if strings.Count(r.stdout, "node  PID 20") != 1 || !strings.Contains(r.stdout, "├── node  PID 20") || !strings.Contains(r.stdout, "└── node  PID 21") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
	if !strings.Contains(r.stdout, "│   addr    0.0.0.0:3000, [::]:3000") {
		t.Errorf("addresses not merged:\n%s", r.stdout)
	}
}

func TestPartialRefusalKeepsPortBusy(t *testing.T) {
	f := newFake()
	f.add(3000, 20, "node", "dev")
	f.add(3000, 21, "node", "root")
	r := run(t, f, "", false, "--yes", "3000")
	if f.sent() != "TERM:20" || r.code != ExitRefused {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if !strings.Contains(r.stdout, "still held by PID 21") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestTimeoutWithoutForce(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.stubborn[10] = true
	r := run(t, f, "", false, "--yes", "--timeout", "2s", "3000")
	if r.code != ExitRefused || f.sent() != "TERM:10" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if !strings.Contains(r.stdout, "Port 3000 still held by PID 10 after 2s.\nNot sending SIGKILL without --force.") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestForceEscalates(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.stubborn[10] = true
	r := run(t, f, "", false, "--yes", "--force", "3000")
	if r.code != ExitFreed || f.sent() != "TERM:10 KILL:10" {
		t.Fatalf("code=%d sent=%q out=%s", r.code, f.sent(), r.stdout)
	}
}

func TestInteractiveEscalation(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.stubborn[10] = true
	r := run(t, f, "y\ny\n", true, "3000")
	if r.code != ExitFreed || f.sent() != "TERM:10 KILL:10" || !strings.Contains(r.stdout, "Send SIGKILL? [y/N]") {
		t.Fatalf("code=%d sent=%q out=%s", r.code, f.sent(), r.stdout)
	}
	f2 := newFake()
	f2.add(3000, 10, "node", "dev")
	f2.stubborn[10] = true
	if r := run(t, f2, "y\nn\n", true, "3000"); r.code != ExitRefused || f2.sent() != "TERM:10" {
		t.Fatalf("decline kill: code=%d sent=%q", r.code, f2.sent())
	}
}

func TestSurvivesSIGKILL(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.immortal[10] = true
	r := run(t, f, "", false, "--yes", "--force", "3000")
	if r.code != ExitError || f.sent() != "TERM:10 KILL:10" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
}

func TestRespawnDetected(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.respawn[10] = 11
	r := run(t, f, "", false, "--yes", "3000")
	if r.code != ExitError || !strings.Contains(r.stdout, "taken again by PID 11 (node)") {
		t.Fatalf("code=%d out=%s", r.code, r.stdout)
	}
}

func TestFreedButProbeStillAnswers(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	r := run(t, f, "", false, "--yes", "3000")
	if r.code != ExitFreed {
		t.Fatalf("baseline code=%d", r.code)
	}
	f2 := newFake()
	f2.add(3000, 10, "node", "dev")
	f2.setProbe(3000, true)
	r = run(t, f2, "", false, "--yes", "3000")
	if r.code != ExitError || !strings.Contains(r.stdout, "owner is not visible") {
		t.Fatalf("code=%d out=%s", r.code, r.stdout)
	}
}

func TestSignalErrors(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.signalErr[10] = sys.ErrPermission
	r := run(t, f, "", false, "--yes", "3000")
	if r.code != ExitError || !strings.Contains(r.stderr, "permission denied") {
		t.Errorf("perm: code=%d err=%q", r.code, r.stderr)
	}

	f2 := newFake()
	f2.add(3000, 10, "node", "dev")
	f2.signalErr[10] = sys.ErrGone
	f2.socks = nil // it exited between discovery and signal
	f2.socks = append(f2.socks, parse.Socket{Proto: "tcp", Host: "*", Port: 3000, PID: 10, Name: "node"})
	r = run(t, f2, "", false, "--yes", "3000")
	if !strings.Contains(r.stdout, "had already exited") {
		t.Errorf("gone: %s", r.stdout)
	}
}

func TestWindowsNoGracefulClose(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node.exe", "dev")
	f.signalErr[10] = sys.ErrNoGraceful
	r := run(t, f, "", false, "--yes", "3000")
	if r.code != ExitRefused || !strings.Contains(r.stdout, "does not accept a graceful close request") ||
		!strings.Contains(r.stdout, "Port 3000 still held by PID 10.\n") {
		t.Fatalf("code=%d out=%s", r.code, r.stdout)
	}
	f2 := newFake()
	f2.add(3000, 10, "node.exe", "dev")
	f2.signalErr[10] = sys.ErrNoGraceful
	// KILL must still be attempted with --force; clear the error once TERM
	// has been seen so the fake dies on KILL.
	calls := 0
	wrapped := &signalHook{fakeSys: f2, before: func(pid int, sig string) {
		calls++
		if sig == "KILL" {
			delete(f2.signalErr, pid)
		}
	}}
	var out bytes.Buffer
	now := fixedNow
	env := Env{Sys: wrapped, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out,
		Getenv: func(string) string { return "" }, Now: func() time.Time { return now },
		Sleep: func(d time.Duration) { now = now.Add(d) }, GOOS: "windows", ParseSignal: parseSig}
	if code := Run([]string{"--yes", "--force", "3000"}, env); code != ExitFreed || f2.sent() != "TERM:10 KILL:10" {
		t.Fatalf("code=%d sent=%q out=%s", code, f2.sent(), out.String())
	}
	if now.Sub(fixedNow) > time.Second {
		t.Errorf("waited %v for a process that cannot close gracefully", now.Sub(fixedNow))
	}
}

type signalHook struct {
	*fakeSys
	before func(pid int, sig string)
}

func (s *signalHook) Signal(pid int, sig string) error {
	s.before(pid, sig)
	return s.fakeSys.Signal(pid, sig)
}

func TestRecheckBeforeSignal(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	// The process exits while the user is at the prompt.
	in := &hookReader{r: strings.NewReader("y\n"), onRead: func() { f.socks = nil }}
	var out, errb bytes.Buffer
	env := Env{Sys: f, Stdin: in, Stdout: &out, Stderr: &errb, StdinTTY: true,
		Getenv: func(string) string { return "" }, Now: func() time.Time { return fixedNow },
		Sleep: func(time.Duration) {}, GOOS: "linux", ParseSignal: parseSig}
	code := Run([]string{"3000"}, env)
	if f.sent() != "" || code != ExitFreed || !strings.Contains(out.String(), "PID 10 is no longer listening on port 3000; not signalling it.") {
		t.Errorf("code=%d sent=%q out=%s", code, f.sent(), out.String())
	}
}

type hookReader struct {
	r      *strings.Reader
	onRead func()
}

func (h *hookReader) Read(p []byte) (int, error) {
	if h.onRead != nil {
		h.onRead()
		h.onRead = nil
	}
	return h.r.Read(p)
}

func TestDryRun(t *testing.T) {
	f := newFake()
	f.add(8080, 10, "java", "dev")
	r := run(t, f, "", false, "--dry-run", "8080")
	if r.code != ExitFreed || f.sent() != "" || !strings.Contains(r.stdout, "Would send SIGTERM to PID 10 (java).") {
		t.Errorf("code=%d sent=%q out=%s", r.code, f.sent(), r.stdout)
	}
}

func TestCustomSignal(t *testing.T) {
	f := newFake()
	f.add(8080, 10, "java", "dev")
	if r := run(t, f, "", false, "--yes", "--signal", "sigint", "8080"); r.code != ExitFreed || f.sent() != "INT:10" {
		t.Errorf("code=%d sent=%q", r.code, f.sent())
	}
	if r := run(t, f, "", false, "--signal=BOGUS", "8080"); r.code != ExitError || !strings.Contains(r.stderr, "unsupported signal") {
		t.Errorf("bogus: code=%d err=%q", r.code, r.stderr)
	}
}

func TestMultiplePortsAndRanges(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.add(8003, 11, "python3", "dev")
	r := run(t, f, "", false, "--yes", "3000", "5173", "8000-8005")
	if r.code != ExitFreed || f.sent() != "TERM:10 TERM:11" {
		t.Fatalf("code=%d sent=%q", r.code, f.sent())
	}
	if !strings.HasSuffix(r.stdout, "\nNothing listening on tcp ports 5173, 8000-8002, 8004-8005.\n") {
		t.Errorf("stdout:\n%s", r.stdout)
	}
}

func TestExitCodePrecedence(t *testing.T) {
	tests := []struct {
		results []string
		want    int
	}{
		{[]string{ResultNotListening}, ExitNotListening},
		{[]string{ResultFreed, ResultNotListening}, ExitFreed},
		{[]string{ResultFreed, ResultDeclined}, ExitRefused},
		{[]string{ResultRefused, ResultError}, ExitError},
		{[]string{ResultStillListening, ResultFreed}, ExitError},
		{[]string{ResultDryRun}, ExitFreed},
	}
	for _, tt := range tests {
		var reps []*PortReport
		for _, res := range tt.results {
			reps = append(reps, &PortReport{Result: res})
		}
		if got := exitCode(reps); got != tt.want {
			t.Errorf("exitCode(%v) = %d, want %d", tt.results, got, tt.want)
		}
	}
}

func TestJSONShape(t *testing.T) {
	f := newFake()
	f.add(3000, 42192, "node", "dev", "*")
	f.procs[42192].Cmd = "node server.js --token=abc"
	r := run(t, f, "", false, "--json", "--yes", "3000", "4000")
	var got map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", r.stdout, err)
	}
	if got["exit_code"].(float64) != 0 {
		t.Errorf("exit_code = %v", got["exit_code"])
	}
	ports := got["ports"].([]any)
	p0 := ports[0].(map[string]any)
	proc := p0["processes"].([]any)[0].(map[string]any)
	if p0["result"] != "freed" || proc["pid"].(float64) != 42192 || proc["user"] != "dev" ||
		proc["started"] != "2026-09-17T09:47:00Z" || proc["uptime_seconds"].(float64) != 7980 ||
		proc["killable"] != true || proc["cmd"] != "node server.js --token=***" {
		t.Errorf("port 0 = %v", p0)
	}
	if ports[1].(map[string]any)["result"] != "not_listening" {
		t.Errorf("port 1 = %v", ports[1])
	}
	if strings.Contains(r.stdout, "abc") {
		t.Error("secret leaked into JSON")
	}
}

func TestJSONPromptsGoToStderr(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	r := run(t, f, "n\n", true, "--json", "3000")
	if !strings.Contains(r.stderr, "Kill process? [y/N]") || strings.Contains(r.stdout, "Kill process") {
		t.Errorf("stdout=%q stderr=%q", r.stdout, r.stderr)
	}
	if !json.Valid([]byte(r.stdout)) {
		t.Errorf("stdout not JSON: %q", r.stdout)
	}
}

func TestList(t *testing.T) {
	f := newFake()
	f.add(8080, 30, "java", "dev", "*")
	f.add(3000, 10, "node", "dev", "127.0.0.1", "::1")
	f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: "*", Port: 22})
	r := run(t, f, "", false, "--list")
	want := `PORT  PROTO  PID  USER  PROCESS  ADDRESS
22    tcp    ?    ?     ?        *:22
3000  tcp    10   dev   node     127.0.0.1:3000, [::1]:3000
8080  tcp    30   dev   java     *:8080
`
	if r.code != 0 || r.stdout != want {
		t.Errorf("code=%d stdout:\n%s\nwant:\n%s", r.code, r.stdout, want)
	}
	r = run(t, f, "", false, "--list", "--json", "3000")
	var got struct{ Listeners []ListEntry }
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil || len(got.Listeners) != 1 || got.Listeners[0].PID != 10 || len(got.Listeners[0].Addresses) != 2 {
		t.Errorf("json = %s (%v)", r.stdout, err)
	}
	empty := newFake()
	r = run(t, empty, "", false, "--list", "--json")
	if r.code != ExitNotListening || !strings.Contains(r.stdout, `"listeners": []`) {
		t.Errorf("empty list code=%d out=%s", r.code, r.stdout)
	}
}

func TestDiscoveryError(t *testing.T) {
	f := newFake()
	f.listErr = errors.New("lsof not found")
	r := run(t, f, "", false, "3000")
	if r.code != ExitError || !strings.Contains(r.stderr, "lsof not found") {
		t.Errorf("code=%d err=%q", r.code, r.stderr)
	}
}

func TestArgs(t *testing.T) {
	f := newFake()
	tests := []struct {
		args    []string
		code    int
		stdout  string
		stderr  string
		comment string
	}{
		{args: []string{"--version"}, code: 0, stdout: "portkill 0.2.0\n"},
		{args: []string{"-h"}, code: 0, stdout: "Usage:"},
		{args: []string{}, code: ExitError, stderr: "no port given"},
		{args: []string{"99999"}, code: ExitError, stderr: "between 1 and 65535"},
		{args: []string{"--bogus", "3000"}, code: ExitError, stderr: "flag provided but not defined"},
		{args: []string{"--timeout", "0s", "3000"}, code: ExitError, stderr: "--timeout must be positive"},
		{args: []string{"3000", "--timeout", "1s"}, code: ExitNotListening, stdout: "nothing listening"},
		{args: []string{"--", "3000"}, code: ExitNotListening, stdout: "nothing listening"},
	}
	for _, tt := range tests {
		r := run(t, f, "", false, tt.args...)
		if r.code != tt.code || !strings.Contains(r.stdout, tt.stdout) || !strings.Contains(r.stderr, tt.stderr) {
			t.Errorf("%v: code=%d stdout=%q stderr=%q", tt.args, r.code, r.stdout, r.stderr)
		}
	}
}

func TestColor(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	mk := func(noColorEnv string, args ...string) string {
		var out bytes.Buffer
		env := Env{Sys: f, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &out, StdoutTTY: true,
			Getenv: func(k string) string {
				if k == "NO_COLOR" {
					return noColorEnv
				}
				return ""
			},
			Now: func() time.Time { return fixedNow }, Sleep: func(time.Duration) {}, GOOS: "linux", ParseSignal: parseSig}
		Run(append(args, "--dry-run", "3000"), env)
		return out.String()
	}
	if !strings.Contains(mk(""), "\x1b[1m") {
		t.Error("expected colour on a TTY")
	}
	if strings.Contains(mk("1"), "\x1b[") {
		t.Error("NO_COLOR ignored")
	}
	if strings.Contains(mk("", "--no-color"), "\x1b[") {
		t.Error("--no-color ignored")
	}
}

func TestFormatUptime(t *testing.T) {
	tests := map[time.Duration]string{
		-time.Second:                   "0s",
		45 * time.Second:               "45s",
		12*time.Minute + 5*time.Second: "12m",
		2*time.Hour + 13*time.Minute:   "2h13m",
		76 * time.Hour:                 "3d4h",
	}
	for d, want := range tests {
		if got := FormatUptime(d); got != want {
			t.Errorf("FormatUptime(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestTildify(t *testing.T) {
	r := &runner{env: Env{Home: "/home/dev", GOOS: "linux"}}
	for in, want := range map[string]string{
		"/home/dev":          "~",
		"/home/dev/code/app": "~/code/app",
		"/home/developer":    "/home/developer",
		"/":                  "/",
	} {
		if got := r.tildify(in); got != want {
			t.Errorf("tildify(%q) = %q", in, got)
		}
	}
	w := &runner{env: Env{Home: `C:\Users\dev`, GOOS: "windows"}}
	if got := w.tildify(`C:\Users\dev\app`); got != `~\app` {
		t.Errorf("windows tildify = %q", got)
	}
}
