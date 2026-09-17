package parse

import (
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ProcSocket is a socket row from /proc/net/{tcp,tcp6,udp,udp6}. The owning
// PID is not in that file; it is found by matching Inode against the
// "socket:[inode]" links under /proc/<pid>/fd.
type ProcSocket struct {
	Socket
	Inode uint64
}

// ProcNet parses /proc/net/tcp, tcp6, udp or udp6. Addresses are hex in host
// byte order, so the caller passes the machine's order (tests pass
// binary.LittleEndian). For TCP only LISTEN rows (state 0A) are returned; for
// UDP only rows with no remote peer (remote port 0).
func ProcNet(data, proto string, order binary.ByteOrder, want map[int]bool) []ProcSocket {
	var res []ProcSocket
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 10 || !strings.HasSuffix(f[0], ":") {
			continue // header or malformed
		}
		localHex, remHex, state := f[1], f[2], f[3]
		if proto == "tcp" && state != "0A" {
			continue
		}
		host, port, ok := procAddr(localHex, order)
		if !ok || port == 0 || (want != nil && !want[port]) {
			continue
		}
		if proto == "udp" {
			if _, rport, ok := procAddr(remHex, order); !ok || rport != 0 {
				continue
			}
		}
		inode, err := strconv.ParseUint(f[9], 10, 64)
		if err != nil {
			continue
		}
		res = append(res, ProcSocket{
			Socket: Socket{Proto: proto, Host: wildcard(host), Port: port},
			Inode:  inode,
		})
	}
	return res
}

func procAddr(s string, order binary.ByteOrder) (string, int, bool) {
	hexIP, hexPort, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, false
	}
	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return "", 0, false
	}
	var ip net.IP
	switch len(hexIP) {
	case 8:
		v, err := strconv.ParseUint(hexIP, 16, 32)
		if err != nil {
			return "", 0, false
		}
		ip = make(net.IP, 4)
		order.PutUint32(ip, uint32(v))
	case 32:
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hexIP[i*8:i*8+8], 16, 32)
			if err != nil {
				return "", 0, false
			}
			order.PutUint32(ip[i*4:], uint32(v))
		}
		if v4 := ip.To4(); v4 != nil && !ip.Equal(net.IPv6zero) && !ip.Equal(net.IPv6loopback) {
			ip = v4 // IPv4-mapped (::ffff:a.b.c.d)
		}
	default:
		return "", 0, false
	}
	return ip.String(), int(port), true
}

// FdSocketInode extracts the inode from an fd symlink target such as
// "socket:[123456]".
func FdSocketInode(link string) (uint64, bool) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	n, err := strconv.ParseUint(link[len("socket:["):len(link)-1], 10, 64)
	return n, err == nil
}

// ProcStat holds the fields portkill needs from /proc/<pid>/stat.
type ProcStat struct {
	Comm      string
	PPID      int
	StartTick uint64 // clock ticks since boot
}

// ParseProcStat parses /proc/<pid>/stat. The command name is in parentheses
// and may itself contain spaces and parentheses, so fields are counted from
// the last ')'.
func ParseProcStat(data string) (ProcStat, bool) {
	open := strings.IndexByte(data, '(')
	closeIdx := strings.LastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return ProcStat{}, false
	}
	rest := strings.Fields(data[closeIdx+1:])
	// rest[0] is field 3 (state); ppid is field 4; starttime is field 22.
	if len(rest) < 20 {
		return ProcStat{}, false
	}
	ppid, err1 := strconv.Atoi(rest[1])
	start, err2 := strconv.ParseUint(rest[19], 10, 64)
	if err1 != nil || err2 != nil {
		return ProcStat{}, false
	}
	return ProcStat{Comm: data[open+1 : closeIdx], PPID: ppid, StartTick: start}, true
}

// ProcStatusUID returns the real UID from /proc/<pid>/status.
func ProcStatusUID(data string) (int, bool) {
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "Uid:") {
			f := strings.Fields(line[4:])
			if len(f) == 0 {
				return 0, false
			}
			n, err := strconv.Atoi(f[0])
			return n, err == nil
		}
	}
	return 0, false
}

// ProcCmdline turns the NUL separated /proc/<pid>/cmdline into one line.
func ProcCmdline(data []byte) string {
	s := strings.TrimRight(string(data), "\x00")
	return strings.Join(strings.Split(s, "\x00"), " ")
}

// ProcUptime parses /proc/uptime and returns seconds since boot.
func ProcUptime(data string) (float64, bool) {
	f := strings.Fields(data)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil
}

var ssUserRe = regexp.MustCompile(`\("((?:[^"\\]|\\.)*)",pid=(\d+)`)

// SS parses `ss -Hlntp` / `ss -Hlnup` output. Rows without a users:(...)
// section (sockets of other users when not root) are returned with PID 0.
func SS(out, proto string, want map[int]bool) []Socket {
	var res []Socket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] == "State" || f[0] == "Netid" {
			continue
		}
		if f[0] != "LISTEN" && f[0] != "UNCONN" {
			continue
		}
		local := f[3]
		host, port, ok := splitHostPort(local, false)
		if !ok || port == 0 || (want != nil && !want[port]) {
			continue
		}
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		base := Socket{Proto: proto, Host: wildcard(host), Port: port}
		matches := ssUserRe.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 {
			res = append(res, base)
			continue
		}
		seen := map[int]bool{}
		for _, m := range matches {
			pid, _ := strconv.Atoi(m[2])
			if seen[pid] {
				continue
			}
			seen[pid] = true
			s := base
			s.PID = pid
			s.Name = m[1]
			res = append(res, s)
		}
	}
	return res
}
