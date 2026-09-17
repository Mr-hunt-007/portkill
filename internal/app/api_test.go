package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// apiEnv is an Env whose stdout and stderr must stay untouched by the API.
func apiEnv(f *fakeSys) (Env, *bytes.Buffer) {
	var out bytes.Buffer
	now := fixedNow
	return Env{
		Sys: f, Stdin: strings.NewReader("y\ny\n"), Stdout: &out, Stderr: &out,
		StdinTTY: true, StdoutTTY: true,
		Getenv:      func(string) string { return "" },
		Now:         func() time.Time { return now },
		Sleep:       func(d time.Duration) { now = now.Add(d) },
		GOOS:        "linux",
		ParseSignal: parseSig,
	}, &out
}

func TestInspectNeverSignals(t *testing.T) {
	f := newFake()
	f.add(3000, 10, "node", "dev")
	f.add(8021, 1, "launchd", "root")
	env, out := apiEnv(f)
	rep, err := Inspect(env, []int{3000, 4000, 8021}, false)
	if err != nil {
		t.Fatal(err)
	}
	if f.sent() != "" || out.Len() != 0 {
		t.Fatalf("sent=%q output=%q", f.sent(), out.String())
	}
	got := []string{rep.Ports[0].Result, rep.Ports[1].Result, rep.Ports[2].Result}
	if strings.Join(got, " ") != "dry_run not_listening refused" || rep.ExitCode != ExitRefused {
		t.Errorf("results = %v exit=%d", got, rep.ExitCode)
	}
	if _, err := Inspect(env, nil, false); err == nil {
		t.Error("no ports: want error")
	}
	f.listErr = errors.New("lsof not found")
	if _, err := Inspect(env, []int{3000}, false); err == nil || !strings.Contains(err.Error(), "lsof not found") {
		t.Errorf("discovery error = %v", err)
	}
}

func TestListAPI(t *testing.T) {
	f := newFake()
	env, out := apiEnv(f)
	rep, err := List(env, nil, false)
	if err != nil || rep.Listeners == nil || len(rep.Listeners) != 0 {
		t.Fatalf("empty: %+v %v", rep, err)
	}
	f.add(8080, 30, "java", "dev")
	f.add(3000, 10, "node", "dev")
	rep, _ = List(env, []int{8080}, false)
	if len(rep.Listeners) != 1 || rep.Listeners[0].PID != 30 || out.Len() != 0 {
		t.Errorf("filtered: %+v out=%q", rep.Listeners, out.String())
	}
}

func TestKillPID(t *testing.T) {
	t.Run("kills only the pinned PID", func(t *testing.T) {
		f := newFake()
		f.add(3000, 20, "node", "dev")
		f.add(3000, 21, "node", "dev")
		env, out := apiEnv(f)
		rep, err := KillPID(env, KillRequest{Port: 3000, PID: 21})
		if err != nil {
			t.Fatal(err)
		}
		if f.sent() != "TERM:21" || out.Len() != 0 {
			t.Fatalf("sent=%q out=%q", f.sent(), out.String())
		}
		p := rep.Ports[0]
		if p.Result != ResultRefused || !strings.Contains(p.Message, "still held by PID 20") {
			t.Errorf("report = %+v", p)
		}
	})
	t.Run("freed", func(t *testing.T) {
		f := newFake()
		f.add(3000, 20, "node", "dev")
		env, _ := apiEnv(f)
		rep, err := KillPID(env, KillRequest{Port: 3000, PID: 20})
		if err != nil || rep.Ports[0].Result != ResultFreed || rep.ExitCode != ExitFreed || f.sent() != "TERM:20" {
			t.Fatalf("rep=%+v err=%v sent=%q", rep.Ports[0], err, f.sent())
		}
	})
	t.Run("PID moved to another port", func(t *testing.T) {
		f := newFake()
		f.add(3000, 20, "node", "dev")
		f.add(4000, 30, "node", "dev")
		env, _ := apiEnv(f)
		_, err := KillPID(env, KillRequest{Port: 3000, PID: 30, Force: true})
		var missing *PIDNotListeningError
		if !errors.As(err, &missing) || !strings.Contains(err.Error(), "held by PID 20") || f.sent() != "" {
			t.Fatalf("err=%v sent=%q", err, f.sent())
		}
	})
	t.Run("port empty", func(t *testing.T) {
		f := newFake()
		env, _ := apiEnv(f)
		_, err := KillPID(env, KillRequest{Port: 3000, PID: 30})
		var missing *PIDNotListeningError
		if !errors.As(err, &missing) || !strings.Contains(err.Error(), "nothing is listening on tcp port 3000, so PID 30 was not signalled") {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("refusals still apply", func(t *testing.T) {
		f := newFake()
		f.add(80, 1, "launchd", "root")
		f.add(81, 998, "agent", "dev") // the MCP client that started portkill
		f.add(82, 70, "nginx", "root")
		f.add(83, 300, "com.docker.backend", "dev")
		f.socks = append(f.socks, f.socks[0])
		f.socks[len(f.socks)-1].Port, f.socks[len(f.socks)-1].PID = 84, 0
		env, _ := apiEnv(f)
		for _, tt := range []struct{ port, pid int }{{80, 1}, {81, 998}, {82, 70}, {83, 300}, {84, 0}} {
			rep, err := KillPID(env, KillRequest{Port: tt.port, PID: tt.pid, Force: true})
			if err != nil || rep.Ports[0].Result != ResultRefused || !strings.Contains(rep.Ports[0].Message, "will not be killed") {
				t.Errorf("port %d pid %d: rep=%+v err=%v", tt.port, tt.pid, rep.Ports[0], err)
			}
		}
		if f.sent() != "" {
			t.Errorf("sent %q", f.sent())
		}
	})
	t.Run("stubborn without force is declined, never prompts", func(t *testing.T) {
		f := newFake()
		f.add(3000, 20, "node", "dev")
		f.stubborn[20] = true
		env, _ := apiEnv(f)
		rep, _ := KillPID(env, KillRequest{Port: 3000, PID: 20, Timeout: time.Second})
		if rep.Ports[0].Result != ResultDeclined || f.sent() != "TERM:20" {
			t.Fatalf("rep=%+v sent=%q", rep.Ports[0], f.sent())
		}
		rep, _ = KillPID(env, KillRequest{Port: 3000, PID: 20, Force: true, Signal: "INT", Timeout: time.Second})
		if rep.Ports[0].Result != ResultFreed || f.sent() != "TERM:20 INT:20 KILL:20" {
			t.Fatalf("force: rep=%+v sent=%q", rep.Ports[0], f.sent())
		}
	})
	t.Run("validation", func(t *testing.T) {
		env, _ := apiEnv(newFake())
		if _, err := KillPID(env, KillRequest{Port: 0, PID: 1}); err == nil {
			t.Error("port 0 accepted")
		}
		if _, err := KillPID(env, KillRequest{Port: 80, PID: -1}); err == nil {
			t.Error("negative pid accepted")
		}
	})
}

func TestMCPFlags(t *testing.T) {
	f := newFake()
	r := run(t, f, "", false, "--allow-destructive")
	if r.code != ExitError || !strings.Contains(r.stderr, "only applies together with --mcp") {
		t.Errorf("code=%d stderr=%q", r.code, r.stderr)
	}
	r = run(t, f, "", false, "--mcp")
	if r.code != ExitError || !strings.Contains(r.stderr, "not available") {
		t.Errorf("nil ServeMCP: code=%d stderr=%q", r.code, r.stderr)
	}
	var got []bool
	env, _ := apiEnv(f)
	env.ServeMCP = func(allow bool) int { got = append(got, allow); return 0 }
	for _, args := range [][]string{{"--mcp"}, {"--mcp", "--allow-destructive", "--json", "3000"}} {
		if code := Run(args, env); code != 0 {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if len(got) != 2 || got[0] || !got[1] {
		t.Errorf("ServeMCP calls = %v", got)
	}
}
