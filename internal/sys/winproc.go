package sys

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Mr-hunt-007/portkill/internal/parse"
)

func listenersWindows(proto string, ports []int) ([]parse.Socket, []string, error) {
	want := wantSet(ports)
	families := []string{"TCP", "TCPv6"}
	if proto == "udp" {
		families = []string{"UDP", "UDPv6"}
	}
	var socks []parse.Socket
	var lastErr error
	ok := 0
	for _, fam := range families {
		out, err := run("netstat", "-ano", "-p", fam)
		if err != nil && out == "" {
			lastErr = err
			continue
		}
		ok++
		socks = append(socks, parse.NetstatWindows(out, want)...)
	}
	if ok == 0 {
		return nil, nil, lastErr
	}
	if len(socks) > 0 {
		if out, err := run("tasklist", "/FO", "CSV", "/NH"); err == nil {
			names := parse.Tasklist(out)
			for i := range socks {
				socks[i].Name = names[socks[i].PID]
			}
		}
	}
	return socks, nil, nil
}

// windowsDetailsScript queries Win32_Process for the given PIDs and emits
// JSON consumed by parse.WinProcs.
func windowsDetailsScript(pids []int) string {
	conds := make([]string, len(pids))
	for i, p := range pids {
		conds[i] = "ProcessId=" + strconv.Itoa(p)
	}
	return fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'
$rows = @(Get-CimInstance Win32_Process -Filter "%s" | ForEach-Object {
  $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
  $s = ''
  if ($_.CreationDate) { $s = $_.CreationDate.ToUniversalTime().ToString('o') }
  [pscustomobject]@{ pid=[int]$_.ProcessId; ppid=[int]$_.ParentProcessId; cmd=[string]$_.CommandLine; exe=[string]$_.ExecutablePath; owner=[string]$o.User; start=$s }
})
ConvertTo-Json -Compress -InputObject $rows`, strings.Join(conds, " OR "))
}

func detailsWindows(pids []int) map[int]*Proc {
	res := map[int]*Proc{}
	if len(pids) == 0 {
		return res
	}
	names := map[int]string{}
	if out, err := run("tasklist", "/FO", "CSV", "/NH"); err == nil {
		names = parse.Tasklist(out)
	}
	for _, pid := range pids {
		if n, ok := names[pid]; ok {
			res[pid] = &Proc{PID: pid, Name: n}
		}
	}
	out, err := run("powershell", "-NoProfile", "-NonInteractive", "-Command", windowsDetailsScript(pids))
	if err != nil && out == "" {
		return res
	}
	procs, err := parse.WinProcs(out)
	if err != nil {
		return res
	}
	for _, wp := range procs {
		p, ok := res[wp.PID]
		if !ok {
			p = &Proc{PID: wp.PID, Name: baseName(wp.Exe)}
			res[wp.PID] = p
		}
		p.PPID = wp.PPID
		p.ParentName = names[wp.PPID]
		p.Cmd = wp.Cmd
		p.User = wp.Owner
		p.Start = wp.Start
	}
	return res
}
