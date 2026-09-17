package parse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// PsRow is one row of `ps -o pid=,ppid=,user=,etime=,comm=`.
type PsRow struct {
	PID     int
	PPID    int
	User    string
	Elapsed time.Duration
	Comm    string
}

// Ps parses `ps -o pid=,ppid=,user=,etime=,comm=`. comm is last because it
// may contain spaces (macOS prints the full executable path).
func Ps(out string) map[int]PsRow {
	res := map[int]PsRow{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		el, err3 := Etime(f[3])
		if err1 != nil || err2 != nil || err3 != nil {
			continue
		}
		// Re-slice the original line so runs of spaces inside comm survive.
		comm := restAfterFields(line, 4)
		res[pid] = PsRow{PID: pid, PPID: ppid, User: f[2], Elapsed: el, Comm: comm}
	}
	return res
}

// PsArgs parses `ps -ww -o pid=,args=` into PID to full command line.
func PsArgs(out string) map[int]string {
	res := map[int]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pid, err := strconv.Atoi(f[0])
		if err != nil {
			continue
		}
		res[pid] = restAfterFields(line, 1)
	}
	return res
}

func restAfterFields(line string, n int) string {
	s := strings.TrimRight(line, "\r")
	for i := 0; i < n; i++ {
		s = strings.TrimLeft(s, " \t")
		j := strings.IndexAny(s, " \t")
		if j < 0 {
			return ""
		}
		s = s[j:]
	}
	return strings.TrimSpace(s)
}

// Etime parses the ps elapsed time format "[[dd-]hh:]mm:ss".
func Etime(s string) (time.Duration, error) {
	var days int
	if d, rest, ok := strings.Cut(s, "-"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, fmt.Errorf("bad etime %q", s)
		}
		days, s = n, rest
	}
	parts := strings.Split(s, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("bad etime %q", s)
	}
	var total int
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("bad etime %q", s)
		}
		total = total*60 + n
	}
	return time.Duration(days)*24*time.Hour + time.Duration(total)*time.Second, nil
}

// LsofCwd parses `lsof -a -p <pids> -d cwd -Fn` into PID to working directory.
func LsofCwd(out string) map[int]string {
	res := map[int]string{}
	pid := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		switch line[0] {
		case 'p':
			pid, _ = strconv.Atoi(line[1:])
		case 'n':
			if pid != 0 {
				res[pid] = line[1:]
			}
		}
	}
	return res
}

// DockerListener reports whether a process name belongs to a container
// runtime's port forwarder rather than to the application itself. Killing
// one of these takes down every published port, not just this one.
func DockerListener(name string) bool {
	switch strings.ToLower(strings.TrimSuffix(name, ".exe")) {
	case "com.docker.backend", "com.docker.vpnkit", "docker-proxy", "vpnkit",
		"com.docker.proxy", "orbstack helper":
		return true
	}
	return false
}

// DockerContainers parses `docker ps --format '{{.Names}}\t{{.Ports}}'` and
// returns the containers publishing host port on proto. Port specs look like
// "0.0.0.0:8080->80/tcp", "[::]:8080->80/tcp", ":::8080->80/tcp" and ranges
// "0.0.0.0:8000-8010->8000-8010/tcp".
func DockerContainers(out string, port int, proto string) []string {
	var res []string
	for _, line := range strings.Split(out, "\n") {
		name, ports, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok || name == "" {
			continue
		}
		for _, spec := range strings.Split(ports, ",") {
			spec = strings.TrimSpace(spec)
			hostPart, target, ok := strings.Cut(spec, "->")
			if !ok {
				continue
			}
			if _, p, ok := strings.Cut(target, "/"); ok && p != proto {
				continue
			}
			i := strings.LastIndex(hostPart, ":")
			if i < 0 {
				continue
			}
			lo, hi, err := portRange(hostPart[i+1:])
			if err != nil || port < lo || port > hi {
				continue
			}
			res = append(res, name)
			break
		}
	}
	return res
}

var (
	secretFlagRe  = regexp.MustCompile(`(?i)((?:--?|\b)[\w.-]*(?:password|passwd|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credentials?|auth)[\w.-]*)(=|\s+)(\S+)`)
	urlUserinfoRe = regexp.MustCompile(`(://[^/\s:@]+):[^/\s@]+@`)
)

// Redact masks likely secrets in a command line before it is printed:
// values of flags or KEY=value pairs whose name mentions a password, token,
// secret, API key or credential, and passwords in URLs (scheme://user:pass@).
func Redact(cmd string) string {
	cmd = urlUserinfoRe.ReplaceAllString(cmd, "$1:***@")
	return secretFlagRe.ReplaceAllStringFunc(cmd, func(m string) string {
		sub := secretFlagRe.FindStringSubmatch(m)
		name, sep, val := sub[1], sub[2], sub[3]
		// "--token-file /path" names a file, not a secret; a following flag
		// ("--auth --verbose") is not a value either.
		if strings.HasPrefix(val, "-") || strings.Contains(strings.ToLower(name), "file") || strings.Contains(strings.ToLower(name), "path") {
			return m
		}
		// Space-separated values only count for real flags ("--password x"),
		// not for bare words ("auth server.js").
		if sep != "=" && !strings.HasPrefix(name, "-") {
			return m
		}
		return name + sep + "***"
	})
}
