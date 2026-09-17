package app

import (
	"fmt"
	"strings"
	"time"
)

const (
	bold   = "1"
	dim    = "2"
	red    = "31"
	green  = "32"
	yellow = "33"
)

func (r *runner) paint(code, s string) string {
	if !r.color || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (r *runner) renderPort(rep *PortReport) {
	state := "listening"
	if rep.Proto == "udp" {
		state = "bound"
	}
	fmt.Fprintln(r.out, r.paint(bold, fmt.Sprintf("Port %d (%s, %s)", rep.Port, rep.Proto, state)))
	for i, p := range rep.Processes {
		last := i == len(rep.Processes)-1
		branch, indent := "├── ", "│   "
		if last {
			branch, indent = "└── ", "    "
		}
		head := p.Name
		if p.PID > 0 {
			head = fmt.Sprintf("%s  PID %d", p.Name, p.PID)
			if p.User != "" {
				head += "  user " + p.User
			}
			if !p.start.IsZero() {
				head += "  up " + FormatUptime(time.Duration(p.UptimeSeconds)*time.Second)
			}
		}
		fmt.Fprintln(r.out, branch+r.paint(bold, head))
		field := func(label, value string) {
			if value == "" {
				return
			}
			fmt.Fprintf(r.out, "%s%s  %s\n", indent, r.paint(dim, fmt.Sprintf("%-6s", label)), value)
		}
		if p.PPID > 0 {
			parent := fmt.Sprintf("PID %d", p.PPID)
			if p.ParentName != "" {
				parent = fmt.Sprintf("%s (PID %d)", p.ParentName, p.PPID)
			}
			field("parent", parent)
		}
		field("cwd", r.tildify(p.Cwd))
		field("cmd", p.Cmd)
		field("addr", strings.Join(p.Addresses, ", "))
		if p.Refusal != "" {
			fmt.Fprintf(r.out, "%s%s\n", indent, r.paint(yellow, "!  "+p.Refusal))
		}
		if p.Docker != nil {
			if len(p.Docker.Containers) > 0 {
				fmt.Fprintf(r.out, "%s%s\n", indent, "Stop the container instead:")
			} else {
				fmt.Fprintf(r.out, "%s%s\n", indent, "No running container matched this port (is the docker CLI pointed at the right context?). Try:")
			}
			fmt.Fprintf(r.out, "%s   %s\n", indent, r.paint(bold, p.Docker.Hint))
		}
	}
}

func (r *runner) tildify(path string) string {
	home := r.env.Home
	if home == "" || path == "" {
		return path
	}
	if path == home {
		return "~"
	}
	sep := "/"
	if r.env.GOOS == "windows" {
		sep = `\`
	}
	if strings.HasPrefix(path, home+sep) {
		return "~" + path[len(home):]
	}
	return path
}

// FormatUptime renders a duration compactly: "45s", "12m", "2h13m", "3d4h".
func FormatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	s := int64(d / time.Second)
	days, s := s/86400, s%86400
	hours, s := s/3600, s%3600
	mins, secs := s/60, s%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh%dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm", mins)
	}
	return fmt.Sprintf("%ds", secs)
}
