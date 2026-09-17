package sys_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/app"
	"github.com/Mr-hunt-007/portkill/internal/sys"
)

// TestMain doubles as a helper listener process: when PORTKILL_HELPER is set
// the test binary listens on a free loopback port, prints it, and waits to be
// killed.
func TestMain(m *testing.M) {
	if os.Getenv("PORTKILL_HELPER") == "1" {
		if os.Getenv("PORTKILL_HELPER_IGNORE_TERM") == "1" {
			signal.Ignore(syscall.SIGTERM)
		}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println(ln.Addr().(*net.TCPAddr).Port)
		for {
			c, err := ln.Accept()
			if err == nil {
				c.Close()
			}
		}
	}
	os.Exit(m.Run())
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

func TestDiscoverOwnTCPListener(t *testing.T) {
	requireTools(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	socks, _, err := sys.OS{}.Listeners("tcp", []int{port})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range socks {
		if s.Port != port {
			t.Errorf("unrequested port in result: %+v", s)
		}
		if s.PID == os.Getpid() {
			found = true
		}
	}
	if !found {
		t.Fatalf("own PID %d not found on port %d: %+v", os.Getpid(), port, socks)
	}
	d := sys.OS{}.Details([]int{os.Getpid()})[os.Getpid()]
	if d == nil || d.Name == "" || d.PPID == 0 {
		t.Fatalf("details = %+v", d)
	}
	if runtime.GOOS != "windows" && d.Cwd == "" {
		t.Errorf("cwd missing: %+v", d)
	}
	if d.Start.IsZero() || time.Since(d.Start) < 0 || time.Since(d.Start) > time.Hour {
		t.Errorf("implausible start time %v", d.Start)
	}
	if !(sys.OS{}).Probe(port) {
		t.Error("Probe did not see the listener")
	}
}

func TestDiscoverOwnUDPSocket(t *testing.T) {
	requireTools(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	socks, _, err := sys.OS{}.Listeners("udp", []int{port})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range socks {
		if s.PID == os.Getpid() && s.Proto == "udp" {
			return
		}
	}
	t.Fatalf("own UDP socket on %d not found: %+v", port, socks)
}

func TestFreePortIsNotListening(t *testing.T) {
	requireTools(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	socks, _, err := sys.OS{}.Listeners("tcp", []int{port})
	if err != nil {
		t.Fatal(err)
	}
	if len(socks) != 0 {
		t.Errorf("closed port reported as listening: %+v", socks)
	}
}

func startHelper(t *testing.T, ignoreTerm bool) (*exec.Cmd, int, chan struct{}) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PORTKILL_HELPER=1")
	if ignoreTerm {
		cmd.Env = append(cmd.Env, "PORTKILL_HELPER_IGNORE_TERM=1")
	}
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
	port, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		cmd.Process.Kill()
		t.Fatalf("helper said %q", line)
	}
	done := make(chan struct{})
	go func() {
		cmd.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("helper PID %d did not exit after Kill", cmd.Process.Pid)
		}
	})
	return cmd, port, done
}

func runPortkill(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	home, _ := os.UserHomeDir()
	env := app.Env{
		Sys: sys.OS{}, Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: os.Getenv, Now: time.Now, Sleep: time.Sleep,
		GOOS: runtime.GOOS, Home: home, ParseSignal: sys.ParseSignal,
	}
	code := app.Run(args, env)
	return code, out.String(), errb.String()
}

func TestKillRealProcess(t *testing.T) {
	requireTools(t)
	cmd, port, done := startHelper(t, false)
	p := strconv.Itoa(port)

	code, out, errOut := runPortkill("--json", p)
	if code != app.ExitRefused {
		t.Fatalf("without --yes on a non-TTY: code=%d out=%s err=%s", code, out, errOut)
	}
	var rep struct {
		Ports []struct {
			Result    string
			Processes []struct {
				PID      int
				Killable bool
			}
		}
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("bad JSON %q: %v", out, err)
	}
	if len(rep.Ports) != 1 || rep.Ports[0].Result != "refused" || len(rep.Ports[0].Processes) != 1 ||
		rep.Ports[0].Processes[0].PID != cmd.Process.Pid || !rep.Ports[0].Processes[0].Killable {
		t.Fatalf("report = %+v", rep)
	}

	// --force so Windows, where console-less processes refuse a graceful
	// close, escalates to taskkill /F instead of stopping.
	code, out, errOut = runPortkill("--yes", "--force", "--timeout", "3s", p)
	if code != app.ExitFreed {
		t.Fatalf("kill: code=%d\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(out, fmt.Sprintf("Port %d is free.", port)) {
		t.Errorf("output: %s", out)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper still running after portkill reported success")
	}
	if code, out, _ := runPortkill(p); code != app.ExitNotListening {
		t.Errorf("after kill: code=%d out=%s", code, out)
	}
}

func TestStubbornProcessNeedsForce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM handling is a Unix concept; Windows is covered by TestKillRealProcess")
	}
	requireTools(t)
	_, port, done := startHelper(t, true)
	p := strconv.Itoa(port)
	code, out, _ := runPortkill("--yes", "--timeout", "500ms", p)
	if code != app.ExitRefused || !strings.Contains(out, "Not sending SIGKILL without --force") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	select {
	case <-done:
		t.Fatal("helper died from SIGTERM although it ignores it")
	default:
	}
	code, out, _ = runPortkill("--yes", "--force", "--timeout", "500ms", p)
	if code != app.ExitFreed || !strings.Contains(out, "Sent SIGKILL") {
		t.Fatalf("force: code=%d out=%s", code, out)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("helper survived SIGKILL")
	}
}
