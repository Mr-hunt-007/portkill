package mcptools

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/app"
	"github.com/Mr-hunt-007/portkill/internal/mcp"
	"github.com/Mr-hunt-007/portkill/internal/parse"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

// TestMain doubles as a helper listener process for the end-to-end test:
// with PORTKILL_HELPER=1 the test binary listens on a free loopback port,
// prints it, and waits to be killed.
func TestMain(m *testing.M) {
	if os.Getenv("PORTKILL_HELPER") == "1" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println(ln.Addr().(*net.TCPAddr).Port)
		for {
			if c, err := ln.Accept(); err == nil {
				c.Close()
			}
		}
	}
	os.Exit(m.Run())
}

// fakeSys is a minimal in-memory OS: a signal removes the PID's sockets.
type fakeSys struct {
	mu      sync.Mutex
	socks   []parse.Socket
	procs   map[int]*sys.Proc
	signals []string
	listErr error
}

func newFake() *fakeSys { return &fakeSys{procs: map[int]*sys.Proc{}} }

func (f *fakeSys) add(port, pid int, name, user string) {
	f.socks = append(f.socks, parse.Socket{Proto: "tcp", Host: "127.0.0.1", Port: port, PID: pid, Name: name})
	f.procs[pid] = &sys.Proc{PID: pid, PPID: 500, ParentName: "zsh", Name: name, User: user,
		Cmd: name + " server.js --token=hunter2", Cwd: "/home/dev/app", Start: time.Now().Add(-time.Minute)}
}

func (f *fakeSys) Listeners(proto string, ports []int) ([]parse.Socket, []string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, fmt.Sprintf("%s:%d", sig, pid))
	var kept []parse.Socket
	for _, s := range f.socks {
		if s.PID != pid {
			kept = append(kept, s)
		}
	}
	f.socks = kept
	return nil
}

func (f *fakeSys) Probe(int) bool              { return false }
func (f *fakeSys) DockerPS() (string, error)   { return "", errors.New("docker CLI not found") }
func (f *fakeSys) Self() (int, int)            { return 999, 998 }
func (f *fakeSys) CurrentUser() (string, bool) { return "dev", false }

func (f *fakeSys) sent() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.signals, " ")
}

func parseSig(s string) (string, error) {
	up := strings.TrimPrefix(strings.ToUpper(s), "SIG")
	switch up {
	case "TERM", "KILL", "INT", "HUP", "QUIT", "USR1", "USR2":
		return up, nil
	}
	return "", fmt.Errorf("unsupported signal %q", s)
}

func fakeEnv(f app.System) app.Env {
	return app.Env{
		Sys: f, Getenv: func(string) string { return "" },
		Now: time.Now, Sleep: func(time.Duration) {}, GOOS: "linux",
		ParseSignal: parseSig,
	}
}

func tool(t *testing.T, s *mcp.Server, name string) mcp.Tool {
	t.Helper()
	for _, tl := range s.Tools {
		if tl.Name == name {
			return tl
		}
	}
	t.Fatalf("tool %s not registered", name)
	return mcp.Tool{}
}

func call(t *testing.T, s *mcp.Server, name, args string) (map[string]any, error) {
	t.Helper()
	res, err := tool(t, s, name).Handler(context.Background(), json.RawMessage(args))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if uerr := json.Unmarshal([]byte(res.Text), &m); uerr != nil {
		t.Fatalf("%s returned non-JSON %q", name, res.Text)
	}
	if res.Structured == nil {
		t.Errorf("%s: no structured content", name)
	}
	return m, nil
}

func TestToolSetAndSafetyClasses(t *testing.T) {
	names := func(s *mcp.Server) string {
		var n []string
		for _, tl := range s.Tools {
			n = append(n, tl.Name)
			if tl.Description == "" || tl.InputSchema == nil {
				t.Errorf("%s: missing description or schema", tl.Name)
			}
			for prop, schema := range tl.InputSchema["properties"].(map[string]any) {
				if schema.(map[string]any)["description"] == "" {
					t.Errorf("%s.%s has no description", tl.Name, prop)
				}
			}
			destructive := *tl.Annotations.DestructiveHint
			if destructive != (tl.Name == "portkill_kill") || *tl.Annotations.ReadOnlyHint == destructive {
				t.Errorf("%s: wrong annotations %+v", tl.Name, tl.Annotations)
			}
		}
		return strings.Join(n, " ")
	}
	if got := names(New(fakeEnv(newFake()), false)); got != "portkill_inspect portkill_list" {
		t.Errorf("default tools = %s", got)
	}
	s := New(fakeEnv(newFake()), true)
	if got := names(s); got != "portkill_inspect portkill_list portkill_kill" {
		t.Errorf("destructive tools = %s", got)
	}
	if !strings.Contains(tool(t, s, "portkill_kill").Description, "no confirmation prompt") {
		t.Error("kill description must say it acts without a prompt")
	}
	if s.Version != app.Version || s.Instructions == "" {
		t.Errorf("server identity %q %q", s.Version, s.Instructions)
	}
}

func TestInspect(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.add(8021, 1, "launchd", "root")
	s := New(fakeEnv(f), true)
	m, err := call(t, s, "portkill_inspect", `{"ports": ["3000", "4000-4001,8021"]}`)
	if err != nil {
		t.Fatal(err)
	}
	ports := m["ports"].([]any)
	var results []string
	for _, p := range ports {
		results = append(results, p.(map[string]any)["result"].(string))
	}
	if strings.Join(results, " ") != "dry_run not_listening not_listening refused" || m["exit_code"].(float64) != 3 {
		t.Errorf("results = %v, exit_code = %v", results, m["exit_code"])
	}
	proc := ports[0].(map[string]any)["processes"].([]any)[0].(map[string]any)
	if proc["pid"].(float64) != 10 || proc["killable"] != true || proc["cmd"] != "node server.js --token=***" {
		t.Errorf("process = %v", proc)
	}
	if f.sent() != "" {
		t.Errorf("inspect signalled %q", f.sent())
	}

	errs := []struct{ args, want string }{
		{`{}`, "ports is required"},
		{`{"ports": []}`, "ports is required"},
		{`{"ports": ["abc"]}`, "abc"},
		{`{"ports": ["70000"]}`, "between 1 and 65535"},
		{`{"ports": ["1-101"]}`, "expand to 101 ports; at most 100"},
		{`{"ports": ["3000"], "port": 3000}`, `unknown field "port"`},
		{`{"ports": "3000"}`, "invalid arguments"},
	}
	for _, e := range errs {
		if _, err := call(t, s, "portkill_inspect", e.args); err == nil || !strings.Contains(err.Error(), e.want) {
			t.Errorf("%s: err = %v, want %q", e.args, err, e.want)
		}
	}
	f.listErr = errors.New("lsof not found")
	if _, err := call(t, s, "portkill_inspect", `{"ports": ["3000"]}`); err == nil || !strings.Contains(err.Error(), "lsof not found") {
		t.Errorf("discovery error = %v", err)
	}
}

func TestList(t *testing.T) {
	f := newFake()
	for i := 0; i < 5; i++ {
		f.add(3000+i, 10+i, "node", "dev")
	}
	s := New(fakeEnv(f), false)
	m, err := call(t, s, "portkill_list", `{}`)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(m["listeners"].([]any)); n != 5 || m["truncated"] != nil || m["total"] != nil {
		t.Errorf("full list: %d entries, %v", n, m)
	}
	m, _ = call(t, s, "portkill_list", `{"limit": 2}`)
	if n := len(m["listeners"].([]any)); n != 2 || m["total"].(float64) != 5 || !strings.Contains(m["truncated"].(string), "first 2 of 5") {
		t.Errorf("limited: %v", m)
	}
	m, _ = call(t, s, "portkill_list", `{"ports": ["3003-3010"]}`)
	if n := len(m["listeners"].([]any)); n != 2 {
		t.Errorf("filtered: %v", m)
	}
	m, _ = call(t, New(fakeEnv(newFake()), false), "portkill_list", `{"udp": true}`)
	if l, ok := m["listeners"].([]any); !ok || len(l) != 0 {
		t.Errorf("empty list must be [], got %v", m)
	}
	for args, want := range map[string]string{
		`{"limit": 0}`:          "limit must be at least 1",
		`{"ports": ["0"]}`:      "between 1 and 65535",
		`{"limit": "ten"}`:      "invalid arguments",
		`{"ports": ["1-65535"]`: "invalid arguments",
	} {
		if _, err := call(t, s, "portkill_list", args); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", args, err, want)
		}
	}
}

func TestKill(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.add(3000, 11, "node", "dev")
	f.add(4000, 20, "python3", "dev")
	f.add(80, 70, "nginx", "root")
	s := New(fakeEnv(f), true)

	errs := []struct{ args, want string }{
		{`{"pid": 10}`, "port is required"},
		{`{"port": 3000}`, "pid is required"},
		{`{"port": 0, "pid": 10}`, "not between 1 and 65535"},
		{`{"port": 3000, "pid": -5}`, "not a valid process ID"},
		{`{"port": 3000, "pid": 10, "signal": "STOP"}`, "unsupported signal"},
		{`{"port": 3000, "pid": 10, "timeout": "5"}`, "not a duration"},
		{`{"port": 3000, "pid": 10, "timeout": "0s"}`, "greater than 0"},
		{`{"port": 3000, "pid": 10, "timeout": "10m"}`, "at most 1m0s"},
		{`{"port": 3000, "pid": 10, "yes": true}`, `unknown field "yes"`},
		{`{"port": 3000, "pid": 20}`, "PID 20 is not listening on tcp port 3000 (it is held by PID 10, 11); nothing was signalled. Call portkill_inspect again"},
		{`{"port": 5000, "pid": 20}`, "nothing is listening on tcp port 5000, so PID 20 was not signalled"},
	}
	for _, e := range errs {
		if _, err := call(t, s, "portkill_kill", e.args); err == nil || !strings.Contains(err.Error(), e.want) {
			t.Errorf("%s: err = %v, want %q", e.args, err, e.want)
		}
	}
	if f.sent() != "" {
		t.Fatalf("validation errors signalled %q", f.sent())
	}

	m, err := call(t, s, "portkill_kill", `{"port": 80, "pid": 70, "force": true}`)
	if err != nil {
		t.Fatal(err)
	}
	p := m["ports"].([]any)[0].(map[string]any)
	if p["result"] != "refused" || !strings.Contains(p["message"].(string), "owned by user root") || f.sent() != "" {
		t.Errorf("other user: %v sent=%q", p, f.sent())
	}

	m, _ = call(t, s, "portkill_kill", `{"port": 4000, "pid": 20, "signal": "SIGINT", "timeout": "500ms"}`)
	p = m["ports"].([]any)[0].(map[string]any)
	proc := p["processes"].([]any)[0].(map[string]any)
	if p["result"] != "freed" || m["exit_code"].(float64) != 0 || f.sent() != "INT:20" || proc["signals_sent"].([]any)[0] != "INT" {
		t.Errorf("kill: %v sent=%q", m, f.sent())
	}

	// Only the pinned PID of a shared port is signalled.
	m, _ = call(t, s, "portkill_kill", `{"port": 3000, "pid": 11}`)
	p = m["ports"].([]any)[0].(map[string]any)
	if f.sent() != "INT:20 TERM:11" || p["result"] != "refused" || !strings.Contains(p["message"].(string), "still held by PID 10") {
		t.Errorf("shared port: %v sent=%q", p, f.sent())
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := tool(t, s, "portkill_kill").Handler(ctx, json.RawMessage(`{"port": 3000, "pid": 10}`)); err == nil || strings.Contains(f.sent(), ":10") {
		t.Errorf("cancelled call: err=%v sent=%q", err, f.sent())
	}
}

// rpc drives a server over pipes.
type rpc struct {
	t   *testing.T
	in  io.WriteCloser
	out *bufio.Scanner
	id  int
}

func serve(t *testing.T, s *mcp.Server) *rpc {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		s.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	t.Cleanup(func() { inW.Close() })
	c := &rpc{t: t, in: inW, out: bufio.NewScanner(outR)}
	c.out.Buffer(make([]byte, 1<<20), 1<<20)
	return c
}

func (c *rpc) request(method string, params any) map[string]any {
	c.t.Helper()
	m := c.raw(method, params)
	res, ok := m["result"].(map[string]any)
	if !ok {
		c.t.Fatalf("%s: error response %v", method, m)
	}
	return res
}

func (c *rpc) raw(method string, params any) map[string]any {
	c.t.Helper()
	c.id++
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		c.t.Fatal(err)
	}
	if !c.out.Scan() {
		c.t.Fatalf("no response to %s", method)
	}
	var m map[string]any
	if err := json.Unmarshal(c.out.Bytes(), &m); err != nil {
		c.t.Fatalf("bad JSON %q", c.out.Text())
	}
	if m["id"].(float64) != float64(c.id) {
		c.t.Fatalf("response id %v, want %d", m["id"], c.id)
	}
	return m
}

func (c *rpc) handshake() {
	c.t.Helper()
	r := c.request("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "0"}})
	if r["serverInfo"].(map[string]any)["name"] != "portkill" || r["instructions"] == "" {
		c.t.Fatalf("initialize = %v", r)
	}
	io.WriteString(c.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n")
}

func (c *rpc) toolNames() string {
	var n []string
	for _, tl := range c.request("tools/list", map[string]any{})["tools"].([]any) {
		n = append(n, tl.(map[string]any)["name"].(string))
	}
	return strings.Join(n, " ")
}

func (c *rpc) callTool(name string, args map[string]any) (map[string]any, bool) {
	r := c.request("tools/call", map[string]any{"name": name, "arguments": args})
	isErr, _ := r["isError"].(bool)
	text := r["content"].([]any)[0].(map[string]any)["text"].(string)
	var m map[string]any
	if !isErr {
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			c.t.Fatalf("%s: text is not JSON: %q", name, text)
		}
	} else {
		m = map[string]any{"error": text}
	}
	return m, isErr
}

func requireTools(t *testing.T) {
	t.Helper()
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/proc/net/tcp"); err != nil {
			t.Skip("/proc/net/tcp not available")
		}
	case "windows":
		if _, err := exec.LookPath("netstat"); err != nil {
			t.Skip("netstat not available")
		}
	default:
		if _, err := exec.LookPath("lsof"); err != nil {
			t.Skip("lsof not installed")
		}
	}
}

func startHelper(t *testing.T) (pid, port int, done chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PORTKILL_HELPER=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("helper did not report a port: %v", err)
	}
	port, err = strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("helper said %q", line)
	}
	done = make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-done
	})
	return cmd.Process.Pid, port, done
}

func realEnv() app.Env {
	return app.Env{
		Sys: sys.OS{}, Getenv: os.Getenv, Now: time.Now, Sleep: time.Sleep,
		GOOS: runtime.GOOS, ParseSignal: sys.ParseSignal,
	}
}

func TestEndToEndOverPipes(t *testing.T) {
	c := serve(t, New(fakeEnv(newFake()), false))
	c.handshake()
	if got := c.toolNames(); got != "portkill_inspect portkill_list" {
		t.Fatalf("tools without --allow-destructive: %s", got)
	}
	m := c.raw("tools/call", map[string]any{"name": "portkill_kill", "arguments": map[string]any{"port": 1, "pid": 1}})
	if e, ok := m["error"].(map[string]any); !ok || !strings.Contains(e["message"].(string), "unknown tool") {
		t.Errorf("kill callable without --allow-destructive: %v", m)
	}
	if m, isErr := c.callTool("portkill_list", map[string]any{}); isErr || m["listeners"] == nil {
		t.Errorf("list over pipes: %v", m)
	}
	if m, isErr := c.callTool("portkill_inspect", map[string]any{"ports": []string{"99999"}}); !isErr || !strings.Contains(m["error"].(string), "65535") {
		t.Errorf("tool error over pipes: %v", m)
	}
}

// TestEndToEndRealProcess runs the MCP server over pipes against the real
// OS: a helper process listens on a port, and the server inspects, lists and
// kills it, then confirms the port is free.
func TestEndToEndRealProcess(t *testing.T) {
	requireTools(t)
	pid, port, done := startHelper(t)
	c := serve(t, New(realEnv(), true))
	c.handshake()
	if got := c.toolNames(); got != "portkill_inspect portkill_kill portkill_list" {
		t.Fatalf("tools with --allow-destructive: %s", got)
	}

	m, isErr := c.callTool("portkill_inspect", map[string]any{"ports": []string{strconv.Itoa(port)}})
	if isErr {
		t.Fatalf("inspect: %v", m)
	}
	p := m["ports"].([]any)[0].(map[string]any)
	proc := p["processes"].([]any)[0].(map[string]any)
	if p["result"] != "dry_run" || int(proc["pid"].(float64)) != pid || proc["killable"] != true {
		t.Fatalf("inspect = %v", p)
	}

	m, isErr = c.callTool("portkill_list", map[string]any{"ports": []string{strconv.Itoa(port)}})
	if l := m["listeners"].([]any); isErr || len(l) != 1 || int(l[0].(map[string]any)["pid"].(float64)) != pid {
		t.Fatalf("list = %v", m)
	}

	// The wrong PID must not touch the helper.
	m, isErr = c.callTool("portkill_kill", map[string]any{"port": port, "pid": os.Getpid()})
	if !isErr || !strings.Contains(m["error"].(string), "nothing was signalled") {
		t.Fatalf("wrong pid: %v", m)
	}
	select {
	case <-done:
		t.Fatal("helper died after a kill with the wrong PID")
	default:
	}

	// force so Windows, where console-less processes refuse a graceful
	// close, escalates to taskkill /F.
	m, isErr = c.callTool("portkill_kill", map[string]any{"port": port, "pid": pid, "force": true, "timeout": "3s"})
	if isErr || m["ports"].([]any)[0].(map[string]any)["result"] != "freed" {
		t.Fatalf("kill = %v", m)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper still running after portkill_kill reported freed")
	}
	m, _ = c.callTool("portkill_inspect", map[string]any{"ports": []string{strconv.Itoa(port)}})
	if r := m["ports"].([]any)[0].(map[string]any)["result"]; r != "not_listening" {
		t.Errorf("after kill: %v", r)
	}
}
