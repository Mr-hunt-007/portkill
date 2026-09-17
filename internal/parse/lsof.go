package parse

import (
	"regexp"
	"strconv"
	"strings"
)

// Lsof parses `lsof -F` field output (one field per line, the first character
// naming the field). A 'p' line starts a process; 'f' starts a file within
// it; 'c' is the command name, 'L' the login name, 'P' the protocol and 'n'
// the address. Only sockets whose local port is in want (or all when want is
// nil) are returned; connected UDP sockets ("a->b") are skipped because they
// are not bound listeners.
func Lsof(out string, want map[int]bool) []Socket {
	var res []Socket
	var pid int
	var name, login string
	var proto string
	flush := func(addr string) {
		if pid == 0 || addr == "" || strings.Contains(addr, "->") {
			return
		}
		host, port, ok := splitHostPort(addr, false)
		if !ok || port == 0 {
			return
		}
		if want != nil && !want[port] {
			return
		}
		res = append(res, Socket{
			Proto: strings.ToLower(proto),
			Host:  wildcard(host),
			Port:  port,
			PID:   pid,
			Name:  name,
			User:  login,
		})
	}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		v := line[1:]
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(v)
			name, login, proto = "", "", ""
		case 'c':
			name = v
		case 'L':
			login = v
		case 'f':
			proto = ""
		case 'P':
			proto = v
		case 'n':
			flush(v)
		}
	}
	return res
}

// netstatDarwinRe matches a row of macOS `netstat -anv -p tcp|udp`. The
// process column ("name:pid") is right aligned, truncated to 16 characters
// and may contain spaces, so it is anchored between the four numeric buffer
// columns before it and the five hex digit state column after it. UDP rows
// have no (state) column.
var netstatDarwinRe = regexp.MustCompile(
	`^(tcp|udp)(?:4|6|46)?\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+(?:([A-Z][A-Z_0-9]*)\s+)?\d+\s+\d+\s+\d+\s+\d+\s+(.+?):(\d+)\s+[0-9a-f]{5}\s`)

// NetstatDarwin parses `netstat -anv -p tcp` (or udp) from macOS 11 and
// later, which reports the owning PID for every socket, including sockets
// owned by other users that an unprivileged lsof cannot see. For TCP only
// LISTEN rows are kept; for UDP only unconnected rows ("*.*").
func NetstatDarwin(out string, want map[int]bool) []Socket {
	var res []Socket
	for _, line := range strings.Split(out, "\n") {
		m := netstatDarwinRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil {
			continue
		}
		proto, local, foreign, state := m[1], m[2], m[3], m[4]
		if proto == "tcp" && state != "LISTEN" {
			continue
		}
		if proto == "udp" && foreign != "*.*" {
			continue
		}
		host, port, ok := splitHostPort(local, true)
		if !ok || port == 0 || (want != nil && !want[port]) {
			continue
		}
		pid, _ := strconv.Atoi(m[6])
		res = append(res, Socket{
			Proto: proto,
			Host:  wildcard(host),
			Port:  port,
			PID:   pid,
			Name:  strings.TrimSpace(m[5]),
		})
	}
	return res
}
