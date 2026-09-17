package parse

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// NetstatWindows parses `netstat -ano -p TCP|TCPv6|UDP|UDPv6`. The state
// column is translated on non-English Windows, so listening TCP sockets are
// recognised by their foreign address having port 0 ("0.0.0.0:0",
// "[::]:0") rather than by the word LISTENING. UDP rows have no state column
// and a foreign address of "*:*".
func NetstatWindows(out string, want map[int]bool) []Socket {
	var res []Socket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimRight(line, "\r"))
		if len(f) < 4 {
			continue
		}
		proto := strings.ToLower(f[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		foreign := f[2]
		if proto == "tcp" {
			if len(f) < 5 {
				continue
			}
			if _, fport, ok := splitHostPort(foreign, false); !ok || fport != 0 {
				continue
			}
		} else if foreign != "*:*" {
			continue
		}
		host, port, ok := splitHostPort(f[1], false)
		if !ok || port == 0 || (want != nil && !want[port]) {
			continue
		}
		if i := strings.IndexByte(host, '%'); i >= 0 {
			host = host[:i]
		}
		pid, err := strconv.Atoi(f[len(f)-1])
		if err != nil {
			continue
		}
		res = append(res, Socket{Proto: proto, Host: wildcard(host), Port: port, PID: pid})
	}
	return res
}

// Tasklist parses `tasklist /FO CSV /NH` (with or without the header row)
// into a PID to image name map. Rows whose second column is not a number,
// such as the header or an "INFO: No tasks" line, are ignored.
func Tasklist(out string) map[int]string {
	r := csv.NewReader(strings.NewReader(out))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	res := map[int]string{}
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if _, ok := err.(*csv.ParseError); ok {
				continue
			}
			break
		}
		if len(rec) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(rec[1]))
		if err != nil {
			continue
		}
		res[pid] = strings.TrimSpace(rec[0])
	}
	return res
}

// WinProc is one process as reported by the PowerShell CIM query portkill
// runs on Windows (see sys.windowsDetailsScript).
type WinProc struct {
	PID   int
	PPID  int
	Cmd   string
	Exe   string
	Owner string
	Start time.Time
}

// WinProcs parses the JSON emitted by ConvertTo-Json for that query. It
// accepts a single object or an array, and a start time either as an ISO
// 8601 string or the Windows PowerShell 5.1 "/Date(ms)/" form.
func WinProcs(data string) ([]WinProc, error) {
	data = strings.TrimSpace(strings.TrimPrefix(data, "\ufeff"))
	if data == "" {
		return nil, nil
	}
	type raw struct {
		PID   int    `json:"pid"`
		PPID  int    `json:"ppid"`
		Cmd   string `json:"cmd"`
		Exe   string `json:"exe"`
		Owner string `json:"owner"`
		Start string `json:"start"`
	}
	var rows []raw
	if strings.HasPrefix(data, "[") {
		if err := json.Unmarshal([]byte(data), &rows); err != nil {
			return nil, err
		}
	} else {
		var one raw
		if err := json.Unmarshal([]byte(data), &one); err != nil {
			return nil, err
		}
		rows = []raw{one}
	}
	res := make([]WinProc, 0, len(rows))
	for _, r := range rows {
		res = append(res, WinProc{
			PID: r.PID, PPID: r.PPID, Cmd: r.Cmd, Exe: r.Exe, Owner: r.Owner,
			Start: winTime(r.Start),
		})
	}
	return res, nil
}

func winTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if strings.HasPrefix(s, "/Date(") {
		inner := strings.TrimSuffix(strings.TrimPrefix(s, "/Date("), ")/")
		if i := strings.IndexAny(inner, "+-"); i > 0 {
			inner = inner[:i]
		}
		ms, err := strconv.ParseInt(inner, 10, 64)
		if err != nil {
			return time.Time{}
		}
		return time.UnixMilli(ms).UTC()
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}
