package parse

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
	"time"
)

func set(ports ...int) map[int]bool {
	m := map[int]bool{}
	for _, p := range ports {
		m[p] = true
	}
	return m
}

func TestPorts(t *testing.T) {
	tests := []struct {
		args    []string
		want    []int
		wantErr string
	}{
		{args: []string{"3000"}, want: []int{3000}},
		{args: []string{"8000-8003", "3000", "8001"}, want: []int{3000, 8000, 8001, 8002, 8003}},
		{args: []string{"5173,3000"}, want: []int{3000, 5173}},
		{args: []string{"65535"}, want: []int{65535}},
		{args: []string{"0"}, wantErr: "between 1 and 65535"},
		{args: []string{"70000"}, wantErr: "between 1 and 65535"},
		{args: []string{"abc"}, wantErr: "not a number"},
		{args: []string{"9000-8000"}, wantErr: "start is after end"},
		{args: []string{"80-x"}, wantErr: "invalid port range"},
		{args: []string{","}, wantErr: "no ports"},
	}
	for _, tt := range tests {
		got, err := Ports(tt.args)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Ports(%v) err = %v, want containing %q", tt.args, err, tt.wantErr)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Ports(%v) = %v, %v; want %v", tt.args, got, err, tt.want)
		}
	}
}

// Captured on macOS 26 with: lsof -nP -w +c 0 -F pcLPn -iTCP -sTCP:LISTEN
// (plus a default -F run, which adds more fields, for robustness).
const lsofMac = `p54256
g54253
R1
cPython
u501
Ljordan
f4
au
l
tIPv6
G0x3;0x2
d0xa6df851a68cde71
o0t0
PTCP
n*:38123
TST=LISTEN
TQR=0
TQS=0
p967
crapportd
Ljordan
f10
PTCP
n*:56966
f11
PTCP
n*:56966
p1065
cControlCenter
Ljordan
f9
PTCP
n*:7000
f10
PTCP
n*:7000
p5043
ctor
Ljordan
f4
PTCP
n127.0.0.1:9050
p21891
cCode Helper (Plugin)
Ljordan
f40
PTCP
n[::1]:60332
`

func TestLsof(t *testing.T) {
	got := Lsof(lsofMac, nil)
	want := []Socket{
		{Proto: "tcp", Host: "*", Port: 38123, PID: 54256, Name: "Python", User: "jordan"},
		{Proto: "tcp", Host: "*", Port: 56966, PID: 967, Name: "rapportd", User: "jordan"},
		{Proto: "tcp", Host: "*", Port: 56966, PID: 967, Name: "rapportd", User: "jordan"},
		{Proto: "tcp", Host: "*", Port: 7000, PID: 1065, Name: "ControlCenter", User: "jordan"},
		{Proto: "tcp", Host: "*", Port: 7000, PID: 1065, Name: "ControlCenter", User: "jordan"},
		{Proto: "tcp", Host: "127.0.0.1", Port: 9050, PID: 5043, Name: "tor", User: "jordan"},
		{Proto: "tcp", Host: "::1", Port: 60332, PID: 21891, Name: "Code Helper (Plugin)", User: "jordan"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Lsof all:\n got %+v\nwant %+v", got, want)
	}
	filtered := Lsof(lsofMac, set(9050))
	if len(filtered) != 1 || filtered[0].PID != 5043 {
		t.Fatalf("Lsof filtered = %+v", filtered)
	}
	if got := filtered[0].Addr(); got != "127.0.0.1:9050" {
		t.Errorf("Addr = %q", got)
	}
	if got := Lsof(lsofMac, set(60332))[0].Addr(); got != "[::1]:60332" {
		t.Errorf("v6 Addr = %q", got)
	}
}

func TestLsofUDPSkipsConnected(t *testing.T) {
	// lsof -iUDP:53 matches the remote port too; connected sockets are not
	// bound listeners and must not be reported.
	out := "p100\ncmDNSResponder\nLroot\nf5\nPUDP\nn*:5353\nf6\nPUDP\nn10.0.0.2:60000->1.1.1.1:53\np200\ncdnsmasq\nf3\nPUDP\nn127.0.0.1:53\n"
	got := Lsof(out, set(53, 5353))
	want := []Socket{
		{Proto: "udp", Host: "*", Port: 5353, PID: 100, Name: "mDNSResponder", User: "root"},
		{Proto: "udp", Host: "127.0.0.1", Port: 53, PID: 200, Name: "dnsmasq"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// Captured on macOS 26 with: netstat -anv -p tcp (trimmed).
const netstatMacTCP = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  10.24.102.43.54589     160.79.104.10.443      ESTABLISHED        15356       178920  131072  131376             curl:53171  00102 00000008 00000000001c3a66 00000081 04000900      2      0 000000
tcp46      0      0  *.38123                *.*                    LISTEN                 0            0  131072  131072           Python:54256  00000 00000006 00000000001c38c0 00000000 00000800      1      0 000000
tcp6       0      0  *.56966                *.*                    LISTEN                 0            0  131072  131072         rapportd:967    00100 00000006 00000000001b29ed 00000001 00000800      1      0 000000
tcp4       0      0  127.0.0.1.60332        *.*                    LISTEN                 0            0  131072  131072 Code Helper (Plu:21891  00100 00000106 0000000000077d4d 00000001 00000800      1      0 000000
tcp4       0      0  127.0.0.1.8021         *.*                    LISTEN                 0            0  131072  131072          launchd:1      00180 00000006 0000000000000996 00000000 00000800      1      0 000000
tcp6       0      0  ::1.8021               *.*                    LISTEN                 0            0  131072  131072          launchd:1      00180 00000006 0000000000000995 00000000 00000800      1      0 000000
`

// Captured on macOS 26 with: netstat -anv -p udp (trimmed, one bound row added).
const netstatMacUDP = `Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
udp4       0      0  10.24.102.43.60109     35.186.224.22.443                          7566         4768 1048576   29040 Google Chrome He:1271   00102 00000000 00000000001c3c34 00000000 04200900      1      0 000002
udp4       0      0  127.0.0.1.38127        *.*                                           0            0  786896    9216           Python:63939  00100 00000000 00000000001c4001 00000000 00000800      1      0 000000
`

func TestNetstatDarwin(t *testing.T) {
	got := NetstatDarwin(netstatMacTCP, nil)
	want := []Socket{
		{Proto: "tcp", Host: "*", Port: 38123, PID: 54256, Name: "Python"},
		{Proto: "tcp", Host: "*", Port: 56966, PID: 967, Name: "rapportd"},
		{Proto: "tcp", Host: "127.0.0.1", Port: 60332, PID: 21891, Name: "Code Helper (Plu"},
		{Proto: "tcp", Host: "127.0.0.1", Port: 8021, PID: 1, Name: "launchd"},
		{Proto: "tcp", Host: "::1", Port: 8021, PID: 1, Name: "launchd"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if got := NetstatDarwin(netstatMacTCP, set(8021)); len(got) != 2 {
		t.Errorf("filtered = %+v", got)
	}
	udp := NetstatDarwin(netstatMacUDP, nil)
	wantUDP := []Socket{{Proto: "udp", Host: "127.0.0.1", Port: 38127, PID: 63939, Name: "Python"}}
	if !reflect.DeepEqual(udp, wantUDP) {
		t.Fatalf("udp got %+v", udp)
	}
}

// /proc/net/tcp and tcp6 in the layout printed by the kernel's
// get_tcp4_sock / get_tcp6_sock (little-endian host).
const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 34567
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 17960
   2: 0200000A:D431 2A00A8C0:01BB 01 00000000:00000000 02:0000045A 00000000  1000        0 99881
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1435 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45678
   1: 00000000000000000000000001000000:0BB8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45679
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 45680
`

const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  195: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 17016 2 0000000000000000 0
  196: 0200000A:9C40 08080808:0035 01 00000000:00000000 00:00000000 00000000  1000        0 17020 2 0000000000000000 0
`

func TestProcNet(t *testing.T) {
	le := binary.LittleEndian
	got := ProcNet(procTCP, "tcp", le, nil)
	want := []ProcSocket{
		{Socket: Socket{Proto: "tcp", Host: "127.0.0.1", Port: 3000}, Inode: 34567},
		{Socket: Socket{Proto: "tcp", Host: "*", Port: 22}, Inode: 17960},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tcp got %+v\nwant %+v", got, want)
	}
	got6 := ProcNet(procTCP6, "tcp", le, nil)
	want6 := []ProcSocket{
		{Socket: Socket{Proto: "tcp", Host: "*", Port: 5173}, Inode: 45678},
		{Socket: Socket{Proto: "tcp", Host: "::1", Port: 3000}, Inode: 45679},
		{Socket: Socket{Proto: "tcp", Host: "127.0.0.1", Port: 8080}, Inode: 45680},
	}
	if !reflect.DeepEqual(got6, want6) {
		t.Fatalf("tcp6 got %+v\nwant %+v", got6, want6)
	}
	if f := ProcNet(procTCP6, "tcp", le, set(3000)); len(f) != 1 || f[0].Inode != 45679 {
		t.Errorf("filtered tcp6 = %+v", f)
	}
	udp := ProcNet(procUDP, "udp", le, nil)
	if len(udp) != 1 || udp[0].Port != 68 || udp[0].Inode != 17016 {
		t.Errorf("udp = %+v", udp)
	}
	// Big-endian hosts store the same address with bytes in network order.
	be := ProcNet("   0: 7F000001:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 \n", "tcp", binary.BigEndian, nil)
	if len(be) != 1 || be[0].Host != "127.0.0.1" {
		t.Errorf("big endian = %+v", be)
	}
}

func TestFdSocketInode(t *testing.T) {
	tests := []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"socket:[34567]", 34567, true},
		{"pipe:[123]", 0, false},
		{"/dev/null", 0, false},
		{"socket:[x]", 0, false},
		{"anon_inode:[eventpoll]", 0, false},
	}
	for _, tt := range tests {
		got, ok := FdSocketInode(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Errorf("FdSocketInode(%q) = %d, %v", tt.in, got, ok)
		}
	}
}

func TestParseProcStat(t *testing.T) {
	stat := "42192 (node (worker) 1) S 4100 42192 4100 34816 42192 4194304 12345 0 0 0 120 30 0 0 20 0 11 0 8123456 1234567890 20000 18446744073709551615 1 1 0 0 0 0 0 16781312 17922 0 0 0 17 3 0 0 0 0 0\n"
	got, ok := ParseProcStat(stat)
	want := ProcStat{Comm: "node (worker) 1", PPID: 4100, StartTick: 8123456}
	if !ok || got != want {
		t.Fatalf("got %+v, %v", got, ok)
	}
	if _, ok := ParseProcStat("garbage"); ok {
		t.Error("garbage parsed")
	}
	if _, ok := ParseProcStat("1 (init) S 0"); ok {
		t.Error("short stat parsed")
	}
}

func TestProcSmallFiles(t *testing.T) {
	status := "Name:\tnode\nUmask:\t0022\nState:\tS (sleeping)\nPid:\t42192\nPPid:\t4100\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n"
	if uid, ok := ProcStatusUID(status); !ok || uid != 1000 {
		t.Errorf("uid = %d, %v", uid, ok)
	}
	if _, ok := ProcStatusUID("Name:\tx\n"); ok {
		t.Error("missing Uid parsed")
	}
	if got := ProcCmdline([]byte("node\x00server.js\x00--port\x003000\x00")); got != "node server.js --port 3000" {
		t.Errorf("cmdline = %q", got)
	}
	if up, ok := ProcUptime("350735.47 234388.90\n"); !ok || up != 350735.47 {
		t.Errorf("uptime = %v", up)
	}
}

// ss -Hlntp output as printed by iproute2 6.x.
const ssTCP = `LISTEN 0      511          0.0.0.0:3000       0.0.0.0:*    users:(("node",pid=42192,fd=19),("node",pid=42193,fd=19))
LISTEN 0      4096         127.0.0.53%lo:53     0.0.0.0:*
LISTEN 0      128             [::]:5173          [::]:*    users:(("vite dev",pid=5000,fd=22))
LISTEN 0      128                *:8080             *:*    users:(("java",pid=777,fd=40),("java",pid=777,fd=41))
`

func TestSS(t *testing.T) {
	got := SS(ssTCP, "tcp", nil)
	want := []Socket{
		{Proto: "tcp", Host: "*", Port: 3000, PID: 42192, Name: "node"},
		{Proto: "tcp", Host: "*", Port: 3000, PID: 42193, Name: "node"},
		{Proto: "tcp", Host: "127.0.0.53", Port: 53},
		{Proto: "tcp", Host: "*", Port: 5173, PID: 5000, Name: "vite dev"},
		{Proto: "tcp", Host: "*", Port: 8080, PID: 777, Name: "java"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	withHeader := "State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process\nUNCONN 0 0 0.0.0.0:68 0.0.0.0:* users:((\"dhclient\",pid=612,fd=6))\n"
	if u := SS(withHeader, "udp", set(68)); len(u) != 1 || u[0].PID != 612 || u[0].Proto != "udp" {
		t.Errorf("udp = %+v", u)
	}
}

// netstat -ano -p TCP / TCPv6 / UDP from Windows 11, including a German
// locale row to prove the state word is not relied on.
const netstatWin = "\r\nActive Connections\r\n\r\n  Proto  Local Address          Foreign Address        State           PID\r\n" +
	"  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1052\r\n" +
	"  TCP    0.0.0.0:3000           0.0.0.0:0              ABHÖREN         8120\r\n" +
	"  TCP    127.0.0.1:3000         127.0.0.1:52144        ESTABLISHED     8120\r\n" +
	"  TCP    [::]:3000              [::]:0                 LISTENING       8120\r\n" +
	"  TCP    [::1]:5173             [::]:0                 LISTENING       9004\r\n" +
	"  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4\r\n" +
	"  UDP    0.0.0.0:5353           *:*                                    2216\r\n" +
	"  UDP    [fe80::1%12]:1900      *:*                                    3100\r\n"

func TestNetstatWindows(t *testing.T) {
	got := NetstatWindows(netstatWin, set(3000, 5173, 80, 5353, 1900))
	want := []Socket{
		{Proto: "tcp", Host: "*", Port: 3000, PID: 8120},
		{Proto: "tcp", Host: "*", Port: 3000, PID: 8120},
		{Proto: "tcp", Host: "::1", Port: 5173, PID: 9004},
		{Proto: "tcp", Host: "*", Port: 80, PID: 4},
		{Proto: "udp", Host: "*", Port: 5353, PID: 2216},
		{Proto: "udp", Host: "fe80::1", Port: 1900, PID: 3100},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got  %+v\nwant %+v", got, want)
	}
	if all := NetstatWindows(netstatWin, nil); len(all) != 7 {
		t.Errorf("unfiltered count = %d", len(all))
	}
}

func TestTasklist(t *testing.T) {
	out := "\"System Idle Process\",\"0\",\"Services\",\"0\",\"8 K\"\r\n" +
		"\"node.exe\",\"8120\",\"Console\",\"1\",\"52,340 K\"\r\n" +
		"\"Code - Insiders.exe\",\"9004\",\"Console\",\"1\",\"101,000 K\"\r\n"
	got := Tasklist(out)
	want := map[int]string{0: "System Idle Process", 8120: "node.exe", 9004: "Code - Insiders.exe"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	withHeader := "\"Image Name\",\"PID\",\"Session Name\",\"Session#\",\"Mem Usage\"\r\n\"cmd.exe\",\"77\",\"Console\",\"1\",\"4,000 K\"\r\n"
	if got := Tasklist(withHeader); len(got) != 1 || got[77] != "cmd.exe" {
		t.Errorf("header = %v", got)
	}
	if got := Tasklist("INFO: No tasks are running which match the specified criteria.\r\n"); len(got) != 0 {
		t.Errorf("info = %v", got)
	}
}

func TestWinProcs(t *testing.T) {
	arr := "\ufeff" + `[{"pid":8120,"ppid":7000,"cmd":"\"C:\\Program Files\\nodejs\\node.exe\" server.js","exe":"C:\\Program Files\\nodejs\\node.exe","owner":"jordan","start":"2026-09-17T13:05:43.1234567Z"},{"pid":9004,"ppid":1,"cmd":"","exe":"","owner":"","start":""}]`
	got, err := WinProcs(arr)
	if err != nil || len(got) != 2 {
		t.Fatalf("got %+v, %v", got, err)
	}
	if got[0].PID != 8120 || got[0].PPID != 7000 || got[0].Owner != "jordan" || !strings.Contains(got[0].Cmd, "server.js") {
		t.Errorf("row 0 = %+v", got[0])
	}
	if got[0].Start.Year() != 2026 || !got[1].Start.IsZero() {
		t.Errorf("start times = %v, %v", got[0].Start, got[1].Start)
	}
	one, err := WinProcs(`{"pid":5,"ppid":4,"cmd":"x","exe":"","owner":"SYSTEM","start":"/Date(1726578343000)/"}`)
	if err != nil || len(one) != 1 || one[0].Start.Unix() != 1726578343 {
		t.Fatalf("single = %+v, %v", one, err)
	}
	if none, err := WinProcs("  \r\n"); err != nil || none != nil {
		t.Errorf("empty = %v, %v", none, err)
	}
	if _, err := WinProcs("{broken"); err == nil {
		t.Error("broken JSON accepted")
	}
}

// Captured on macOS 26 with: ps -o pid=,ppid=,user=,etime=,comm= -p 1,54256,21891
const psMac = `    1     0 root 03-07:43:31 /sbin/launchd
54256     1 jordan      00:01 /opt/homebrew/Cellar/python@3.14/3.14.4/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python
21891 21870 jordan   02:13:04 /Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)
`

func TestPs(t *testing.T) {
	got := Ps(psMac)
	if len(got) != 3 {
		t.Fatalf("rows = %d", len(got))
	}
	if r := got[1]; r.User != "root" || r.PPID != 0 || r.Elapsed != 3*24*time.Hour+7*time.Hour+43*time.Minute+31*time.Second || r.Comm != "/sbin/launchd" {
		t.Errorf("launchd = %+v", r)
	}
	if r := got[21891]; r.Comm != "/Applications/Visual Studio Code.app/Contents/Frameworks/Code Helper (Plugin).app/Contents/MacOS/Code Helper (Plugin)" || r.Elapsed != 2*time.Hour+13*time.Minute+4*time.Second {
		t.Errorf("code helper = %+v", r)
	}
	args := PsArgs("54256 /opt/homebrew/bin/python3 -m http.server 38123\n  812 -zsh\n")
	if args[54256] != "/opt/homebrew/bin/python3 -m http.server 38123" || args[812] != "-zsh" {
		t.Errorf("args = %v", args)
	}
}

func TestEtime(t *testing.T) {
	tests := []struct {
		in   string
		want time.Duration
		err  bool
	}{
		{"00:01", time.Second, false},
		{"59:59", 59*time.Minute + 59*time.Second, false},
		{"2:13:04", 2*time.Hour + 13*time.Minute + 4*time.Second, false},
		{"1-00:00:00", 24 * time.Hour, false},
		{"12", 0, true},
		{"a:b", 0, true},
		{"x-00:00", 0, true},
	}
	for _, tt := range tests {
		got, err := Etime(tt.in)
		if (err != nil) != tt.err || got != tt.want {
			t.Errorf("Etime(%q) = %v, %v", tt.in, got, err)
		}
	}
}

func TestLsofCwd(t *testing.T) {
	// Captured on macOS: lsof -a -p 54256 -d cwd -Fn
	got := LsofCwd("p54256\nfcwd\nn/home/jordan/code/my app\np1\nfcwd\nn/\n")
	want := map[int]string{54256: "/home/jordan/code/my app", 1: "/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestDocker(t *testing.T) {
	for name, want := range map[string]bool{
		"com.docker.backend": true, "docker-proxy": true, "vpnkit": true,
		"com.docker.backend.exe": true, "OrbStack Helper": true,
		"node": false, "docker": false, "dockerd": false,
	} {
		if got := DockerListener(name); got != want {
			t.Errorf("DockerListener(%q) = %v", name, got)
		}
	}
	ps := "web\t0.0.0.0:8080->80/tcp, [::]:8080->80/tcp\n" +
		"db\t127.0.0.1:5432->5432/tcp\n" +
		"range\t0.0.0.0:9000-9005->9000-9005/tcp\n" +
		"dns\t0.0.0.0:53->53/udp\n" +
		"internal\t6379/tcp\n" +
		"old\t:::7000->7000/tcp\n"
	tests := []struct {
		port  int
		proto string
		want  []string
	}{
		{8080, "tcp", []string{"web"}},
		{5432, "tcp", []string{"db"}},
		{9003, "tcp", []string{"range"}},
		{53, "tcp", nil},
		{53, "udp", []string{"dns"}},
		{6379, "tcp", nil},
		{7000, "tcp", []string{"old"}},
		{80, "tcp", nil},
	}
	for _, tt := range tests {
		if got := DockerContainers(ps, tt.port, tt.proto); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("DockerContainers(%d/%s) = %v, want %v", tt.port, tt.proto, got, tt.want)
		}
	}
}

func TestRedact(t *testing.T) {
	tests := []struct{ in, want string }{
		{"node server.js", "node server.js"},
		{"app --password hunter2 --port 3000", "app --password *** --port 3000"},
		{"app --api-key=abc123", "app --api-key=***"},
		{"env GITHUB_TOKEN=ghp_xxx node x.js", "env GITHUB_TOKEN=*** node x.js"},
		{"psql postgres://admin:s3cret@db:5432/app", "psql postgres://admin:***@db:5432/app"},
		{"app --token-file /run/secrets/t", "app --token-file /run/secrets/t"},
		{"app --auth --verbose", "app --auth --verbose"},
		{"node auth-server.js", "node auth-server.js"},
		{"python -m http.server 8000", "python -m http.server 8000"},
	}
	for _, tt := range tests {
		if got := Redact(tt.in); got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
