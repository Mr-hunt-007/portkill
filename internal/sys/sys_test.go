package sys

import (
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/Mr-hunt-007/portkill/internal/parse"
)

func TestParseSignal(t *testing.T) {
	for _, in := range []string{"TERM", "term", "SIGTERM", "15", " sigkill ", "9"} {
		got, err := ParseSignal(in)
		if err != nil {
			t.Errorf("ParseSignal(%q) error %v", in, err)
			continue
		}
		if got != "TERM" && got != "KILL" {
			t.Errorf("ParseSignal(%q) = %q", in, got)
		}
	}
	for _, in := range []string{"", "BOGUS", "999", "SIG"} {
		if _, err := ParseSignal(in); err == nil {
			t.Errorf("ParseSignal(%q) accepted", in)
		}
	}
	if runtime.GOOS != "windows" {
		if got, err := ParseSignal("sighup"); err != nil || got != "HUP" {
			t.Errorf("HUP = %q, %v", got, err)
		}
	} else if _, err := ParseSignal("HUP"); err == nil {
		t.Error("HUP accepted on Windows")
	}
}

func TestLsofSpec(t *testing.T) {
	if got := lsofSpec([]int{8002, 3000, 8000, 8001, 5173}); got != "3000,5173,8000-8002" {
		t.Errorf("lsofSpec = %q", got)
	}
}

func TestMergeSockets(t *testing.T) {
	lsof := []parse.Socket{{Proto: "tcp", Host: "*", Port: 3000, PID: 10, Name: "node"}}
	netstat := []parse.Socket{
		{Proto: "tcp", Host: "*", Port: 3000, PID: 10, Name: "node"},           // exact duplicate
		{Proto: "tcp", Host: "127.0.0.1", Port: 3000, PID: 10, Name: "node"},   // same pid+port, other spelling
		{Proto: "tcp", Host: "127.0.0.1", Port: 8021, PID: 1, Name: "launchd"}, // invisible to lsof
	}
	got := mergeSockets(lsof, netstat)
	want := []parse.Socket{
		{Proto: "tcp", Host: "*", Port: 3000, PID: 10, Name: "node"},
		{Proto: "tcp", Host: "127.0.0.1", Port: 8021, PID: 1, Name: "launchd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
}

func TestMergeResolved(t *testing.T) {
	known := []parse.Socket{
		{Proto: "tcp", Host: "*", Port: 22},                      // owner unknown from /proc
		{Proto: "tcp", Host: "*", Port: 3000, PID: 10},           // resolved already
		{Proto: "tcp", Host: "127.0.0.1", Port: 5432, PID: 0},    // still unknown
		{Proto: "tcp", Host: "::", Port: 22, PID: 0, Name: "v6"}, // same port, second family
	}
	resolved := []parse.Socket{
		{Proto: "tcp", Host: "*", Port: 22, PID: 700, Name: "sshd"},
		{Proto: "tcp", Host: "127.0.0.1", Port: 5432},
	}
	got := mergeResolved(known, resolved)
	want := []parse.Socket{
		{Proto: "tcp", Host: "*", Port: 22, PID: 700, Name: "sshd"},
		{Proto: "tcp", Host: "*", Port: 3000, PID: 10},
		{Proto: "tcp", Host: "127.0.0.1", Port: 5432, PID: 0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if got := mergeResolved(nil, resolved); !reflect.DeepEqual(got, resolved) {
		t.Errorf("nil known = %+v", got)
	}
}

func TestWindowsDetailsScript(t *testing.T) {
	s := windowsDetailsScript([]int{8120, 9004})
	if !strings.Contains(s, `-Filter "ProcessId=8120 OR ProcessId=9004"`) || !strings.Contains(s, "ConvertTo-Json -Compress -InputObject $rows") {
		t.Errorf("script = %s", s)
	}
}

func TestBaseName(t *testing.T) {
	for in, want := range map[string]string{
		"/sbin/launchd":                    "launchd",
		`C:\Program Files\nodejs\node.exe`: "node.exe",
		"node":                             "node",
		"/Applications/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)": "Code Helper (Plugin)",
	} {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q) = %q", in, got)
		}
	}
}

func TestClassifyTaskkill(t *testing.T) {
	base := errors.New("taskkill: exit status 1: ERROR: The process with PID 8912 could not be terminated.")
	cases := []struct {
		signal, output string
		want           error
	}{
		{"TERM", "ERROR: The process with PID 8912 could not be terminated.\nReason: This process can only be terminated forcefully (with /F option).", ErrNoGraceful},
		{"TERM", "ERROR: The process with PID 8912 could not be terminated.", ErrNoGraceful},
		{"KILL", "ERROR: The process with PID 8912 could not be terminated.\nReason: Access is denied.", ErrPermission},
		{"TERM", `ERROR: The process "8912" not found.`, ErrGone},
		{"KILL", "ERROR: The process with PID 8912 could not be terminated.", base},
	}
	for _, c := range cases {
		if got := classifyTaskkill(c.signal, c.output, base); got != c.want {
			t.Errorf("classifyTaskkill(%s, %q) = %v, want %v", c.signal, c.output, got, c.want)
		}
	}
}
