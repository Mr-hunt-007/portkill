package sys

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Mr-hunt-007/portkill/internal/parse"
)

// clockTicks is USER_HZ. It is 100 on every mainstream Linux build and is not
// readable without cgo, so it is assumed.
const clockTicks = 100

func listenersLinux(proto string, ports []int) ([]parse.Socket, []string, error) {
	want := wantSet(ports)
	var rows []parse.ProcSocket
	readable := 0
	for _, f := range []string{proto, proto + "6"} {
		data, err := os.ReadFile("/proc/net/" + f)
		if err != nil {
			continue
		}
		readable++
		rows = append(rows, parse.ProcNet(string(data), proto, binary.NativeEndian, want)...)
	}
	if readable == 0 {
		return linuxFallback(proto, ports, nil)
	}
	if len(rows) == 0 {
		return nil, nil, nil
	}

	owners, denied := inodeOwners()
	var socks []parse.Socket
	unresolved := 0
	for _, r := range rows {
		pids := owners[r.Inode]
		if len(pids) == 0 {
			unresolved++
			socks = append(socks, r.Socket)
			continue
		}
		for _, pid := range pids {
			s := r.Socket
			s.PID = pid
			socks = append(socks, s)
		}
	}
	if unresolved > 0 && denied {
		return linuxFallback(proto, ports, socks)
	}
	return socks, nil, nil
}

// inodeOwners maps socket inodes to the PIDs holding them by reading the
// /proc/<pid>/fd symlinks. denied reports whether any process could not be
// inspected (normally other users' processes when not root).
func inodeOwners() (map[uint64][]int, bool) {
	owners := map[uint64][]int{}
	denied := false
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return owners, true
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				denied = true
			}
			continue
		}
		seen := map[uint64]bool{}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if inode, ok := parse.FdSocketInode(link); ok && !seen[inode] {
				seen[inode] = true
				owners[inode] = append(owners[inode], pid)
			}
		}
	}
	return owners, denied
}

// linuxFallback asks ss, then lsof, for owners when /proc could not resolve
// them. Sockets that remain unowned are kept with PID 0.
func linuxFallback(proto string, ports []int, known []parse.Socket) ([]parse.Socket, []string, error) {
	want := wantSet(ports)
	if _, err := exec.LookPath("ss"); err == nil {
		flag := "-Hlntp"
		if proto == "udp" {
			flag = "-Hlnup"
		}
		if out, err := run("ss", flag); err == nil || out != "" {
			return mergeResolved(known, parse.SS(out, proto, want)), nil, nil
		}
	}
	if _, err := exec.LookPath("lsof"); err == nil {
		socks, notes, err := listenersLsof(proto, ports)
		if err == nil {
			return mergeResolved(known, socks), notes, nil
		}
	}
	if known == nil {
		return nil, nil, fmt.Errorf("cannot read /proc/net/%s and neither ss nor lsof is available", proto)
	}
	return known, nil, nil
}

// mergeResolved fills PID 0 entries in known with owners from resolved, then
// adds anything resolved found that known did not have.
func mergeResolved(known, resolved []parse.Socket) []parse.Socket {
	if known == nil {
		return resolved
	}
	byPort := map[int][]parse.Socket{}
	for _, s := range resolved {
		if s.PID != 0 {
			byPort[s.Port] = append(byPort[s.Port], s)
		}
	}
	var out []parse.Socket
	have := map[[2]int]bool{}
	for _, s := range known {
		if s.PID == 0 {
			if extra := byPort[s.Port]; len(extra) > 0 {
				for _, e := range extra {
					if !have[[2]int{e.Port, e.PID}] {
						have[[2]int{e.Port, e.PID}] = true
						out = append(out, e)
					}
				}
				continue
			}
		}
		have[[2]int{s.Port, s.PID}] = true
		out = append(out, s)
	}
	return out
}

func detailsLinux(pids []int) map[int]*Proc {
	res := map[int]*Proc{}
	var bootAgo float64
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		bootAgo, _ = parse.ProcUptime(string(data))
	}
	now := time.Now()
	for _, pid := range pids {
		dir := filepath.Join("/proc", strconv.Itoa(pid))
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue
		}
		st, ok := parse.ParseProcStat(string(stat))
		if !ok {
			continue
		}
		p := &Proc{PID: pid, PPID: st.PPID, Name: st.Comm}
		if bootAgo > 0 {
			age := bootAgo - float64(st.StartTick)/clockTicks
			if age >= 0 {
				p.Start = now.Add(-time.Duration(age * float64(time.Second))).Truncate(time.Second)
			}
		}
		if data, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
			if uid, ok := parse.ProcStatusUID(string(data)); ok {
				p.User = strconv.Itoa(uid)
				if u, err := user.LookupId(p.User); err == nil {
					p.User = u.Username
				}
			}
		}
		if data, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
			p.Cmd = parse.ProcCmdline(data)
		}
		if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
			p.Cwd = cwd
		}
		if pst, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(st.PPID), "stat")); err == nil {
			if ps, ok := parse.ParseProcStat(string(pst)); ok {
				p.ParentName = ps.Comm
			}
		}
		if p.Cmd == "" {
			p.Cmd = strings.TrimSpace("[" + p.Name + "]")
		}
		res[pid] = p
	}
	return res
}
