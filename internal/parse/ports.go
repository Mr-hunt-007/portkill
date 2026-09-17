// Package parse holds pure parsers for the text that portkill reads from the
// operating system: lsof, netstat, /proc, ss, tasklist, ps and docker. Nothing
// in this package runs commands or touches the filesystem, so every parser is
// tested on every OS against captured sample output.
package parse

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Socket is one listening (TCP) or bound (UDP) socket and, when known, the
// process that owns it. PID 0 means the owner could not be determined.
type Socket struct {
	Proto string // "tcp" or "udp"
	Host  string // "*", "127.0.0.1", "::1", "::"
	Port  int
	PID   int
	Name  string // process name as reported by the source, may be truncated
	User  string // login name when the source reports it
}

// Addr renders host and port the way people type them: "*:3000",
// "127.0.0.1:3000", "[::1]:3000".
func (s Socket) Addr() string {
	return JoinHostPort(s.Host, s.Port)
}

// JoinHostPort brackets IPv6 hosts.
func JoinHostPort(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// Ports parses port arguments: "3000", "8000-8010" and comma lists of either.
// The result is sorted and de-duplicated.
func Ports(args []string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	add := func(p int) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, arg := range args {
		for _, part := range strings.Split(arg, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			lo, hi, err := portRange(part)
			if err != nil {
				return nil, err
			}
			for p := lo; p <= hi; p++ {
				add(p)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	sort.Ints(out)
	return out, nil
}

func portRange(s string) (int, int, error) {
	if a, b, ok := strings.Cut(s, "-"); ok {
		lo, err := onePort(a)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %v", s, err)
		}
		hi, err := onePort(b)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range %q: %v", s, err)
		}
		if lo > hi {
			return 0, 0, fmt.Errorf("invalid port range %q: start is after end", s)
		}
		return lo, hi, nil
	}
	p, err := onePort(s)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port %q: %v", s, err)
	}
	return p, p, nil
}

func onePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("not a number")
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("must be between 1 and 65535")
	}
	return n, nil
}

// splitHostPort splits "host:port", "[v6]:port", "*:port", and the BSD
// netstat form "host.port". Returns ok=false when there is no numeric port.
func splitHostPort(s string, dotted bool) (string, int, bool) {
	sep := ":"
	if dotted {
		sep = "."
	}
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return "", 0, false
	}
	host, ps := s[:i], s[i+1:]
	port, err := strconv.Atoi(ps)
	if err != nil || port < 0 || port > 65535 {
		return "", 0, false
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if host == "" {
		host = "*"
	}
	return host, port, true
}

// wildcard normalises the many spellings of "any address" to "*".
func wildcard(host string) string {
	switch host {
	case "0.0.0.0", "::", "*", "":
		return "*"
	}
	return host
}
