# portkill

Find what is listening on a port, see exactly what it is, and free the port.

```
$ portkill 3000
Port 3000 (tcp, listening)
└── node  PID 36969  user jordan  up 10s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     node server.js 3000
    addr    *:3000
Kill process? [y/N] n
Left running.
```

## Why

`lsof -ti:3000 | xargs kill -9` works until it kills the wrong thing: Docker's
port forwarder (and with it every container port), a process owned by root,
or the shell you are typing in. It also never tells you whether the port is
actually free afterwards.

portkill shows the process first (name, PID, parent, user, working directory,
command line, uptime), asks, sends SIGTERM, waits for the port to be released,
offers SIGKILL only if needed, and then checks the port again. It is one
static binary with no dependencies and does one thing. For browsing ports
interactively, use a port viewer instead.

## Install

```
go install github.com/Mr-hunt-007/portkill@latest
```

`go install` puts the binary in `$(go env GOPATH)/bin` (usually `~/go/bin`). If your shell says `command not found`, add that directory to your `PATH`:

```sh
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc && source ~/.zshrc   # bash: ~/.bashrc
```

On Windows the Go installer adds `%USERPROFILE%\go\bin` to `PATH` for you.

From source:

```
git clone https://github.com/Mr-hunt-007/portkill
cd portkill
go build .
```

Requires Go 1.22 or newer. On macOS `lsof` and `netstat` are used (both ship
with the OS). On Linux nothing extra is needed; `ss` or `lsof` are used only
as a fallback. On Windows `netstat`, `tasklist`, `taskkill` and PowerShell are
used (all built in).

## Usage

```
portkill [flags] PORT [PORT|RANGE ...]
portkill --list [PORT|RANGE ...]
```

Kill without a prompt. portkill still waits for the port to free and verifies it:

```
$ portkill --yes 5173
Port 5173 (tcp, listening)
└── node  PID 36971  user jordan  up 10s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     node cluster.js
    addr    *:5173
Sent SIGTERM to PID 36971 (node).
Port 5173 is free.
```

Several ports; a process that ignores SIGTERM gets SIGKILL because of `--force`:

```
$ portkill --yes --force --timeout 2s 3000 4000
Port 3000 (tcp, listening)
└── node  PID 36969  user jordan  up 20s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     node server.js 3000
    addr    *:3000
Sent SIGTERM to PID 36969 (node).
Port 3000 is free.

Port 4000 (tcp, listening)
└── Python  PID 37462  user jordan  up 1s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     /opt/homebrew/Cellar/python@3.14/3.14.4/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python worker.py 4000
    addr    *:4000
Sent SIGTERM to PID 37462 (Python).
Port 4000 still held by PID 37462 after 2s.
Sent SIGKILL to PID 37462 (Python).
Port 4000 is free.
```

Without `--force`, portkill asks before SIGKILL on a terminal, and stops with
exit code 3 when stdin is not a terminal.

Ranges; ports with nothing on them are summarised on one line:

```
$ portkill 3000 5173 4000-4005 --dry-run
Port 3000 (tcp, listening)
└── node  PID 36969  user jordan  up 2s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     node server.js 3000
    addr    *:3000
Would send SIGTERM to PID 36969 (node).

Port 5173 (tcp, listening)
└── node  PID 36971  user jordan  up 2s
    parent  launchd (PID 1)
    cwd     /private/tmp/my-app
    cmd     node cluster.js
    addr    *:5173
Would send SIGTERM to PID 36971 (node).

Nothing listening on tcp ports 4000-4005.
```

Things portkill will not kill:

```
$ portkill 8021
Port 8021 (tcp, listening)
└── launchd  PID 1  user root  up 3d8h
    cmd     /sbin/launchd
    addr    127.0.0.1:8021, [::1]:8021
    !  PID 1 is the init process; refusing to signal it
```

It also refuses portkill itself, the shell (or agent) that started it, the Windows System
process (PID 4), processes owned by another user unless you run it with sudo,
and listeners whose owner you cannot see. When the listener is Docker's port
forwarder (`com.docker.backend`, `com.docker.vpnkit`, `vpnkit`, `docker-proxy`,
`OrbStack Helper`), it looks up the container publishing that port with
`docker ps` and prints `docker stop <name>` instead of offering to kill.

List listening ports:

```
$ portkill --list
PORT   PROTO  PID    USER    PROCESS               ADDRESS
3000   tcp    36969  jordan  node                  *:3000
5000   tcp    1065   jordan  ControlCenter         *:5000
7000   tcp    1065   jordan  ControlCenter         *:7000
8000   tcp    24070  jordan  Python                127.0.0.1:8000
8000   tcp    24081  jordan  Python                127.0.0.1:8000
8021   tcp    1      root    launchd               127.0.0.1:8021, [::1]:8021
56966  tcp    967    jordan  rapportd              *:56966
```

(Output trimmed.) Port 8000 above is one socket shared by a parent and a
forked child; both PIDs are shown because killing only one would not free it.

## Use with AI agents

The CLI already works well for coding agents: `--json` output with a stable
shape and documented exit codes. portkill also runs as an
[MCP](https://modelcontextprotocol.io) server on stdio with `portkill --mcp`.

The client starts the server itself, so `portkill` must be on the `PATH` the
client sees. GUI apps often do not inherit your shell's `PATH`; if the server
fails to start, use the absolute path of the binary (for example the output
of `echo "$(go env GOPATH)/bin/portkill"`) as the command.

Claude Code (add `--scope user` to enable it in every project):

```
claude mcp add portkill -- portkill --mcp
```

Codex CLI:

```
codex mcp add portkill -- portkill --mcp
```

or in `~/.codex/config.toml`:

```toml
[mcp_servers.portkill]
command = "portkill"
args = ["--mcp"]
```

Cursor, in `.cursor/mcp.json` (or `~/.cursor/mcp.json` for all projects):

```json
{
  "mcpServers": {
    "portkill": { "command": "portkill", "args": ["--mcp"] }
  }
}
```

VS Code, in `.vscode/mcp.json`:

```json
{
  "servers": {
    "portkill": { "type": "stdio", "command": "portkill", "args": ["--mcp"] }
  }
}
```

Gemini CLI, in `~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "portkill": { "command": "portkill", "args": ["--mcp"] }
  }
}
```

Tools:

| Tool | Kind | What it answers |
| --- | --- | --- |
| `portkill_inspect` | read-only | What is listening on these ports (`ports`: `["3000", "8000-8010"]`, `udp`), with the same details and JSON as `--dry-run --json`, including refusals and the Docker hint. At most 100 ports per call. |
| `portkill_list` | read-only | Every listener, as `--list --json`. Capped at 200 entries by default (`limit`); a cut list adds `"total"` and `"truncated"`. |
| `portkill_kill` | destructive | Stops one process: `port` and `pid` (both required), `signal`, `force`, `timeout`. Returns the same JSON as `--yes --json PORT`. Only offered with `--allow-destructive`. |

By default the server only offers the read-only tools. To let an agent kill
processes, start it with `portkill --mcp --allow-destructive` (for example
`claude mcp add portkill -- portkill --mcp --allow-destructive`).
`portkill_kill` then acts immediately, without a confirmation prompt, so only
enable it for agents you trust with that. It is still limited:

- The kill only goes ahead if the given PID is listening on that port at the
  moment of the call, so a process that took the port after the agent looked
  is never hit. Other processes on the same port are left alone.
- Every CLI refusal applies: owner not visible (PID 0), PID 1, the Windows
  System process, portkill itself and the agent that started it, other users'
  processes (unless run as root), and Docker's port forwarder.
- SIGKILL is only sent when `force` is true. The port is checked again
  afterwards and `result` is `freed` only if it is really free.

Command lines stay masked over MCP exactly as in the CLI.

An [Agent Skill](skills/portkill/SKILL.md) teaches agents to use the CLI
directly. Install it for Claude Code:

```
mkdir -p ~/.claude/skills && cp -r skills/portkill ~/.claude/skills/
```

and for Codex CLI:

```
mkdir -p ~/.agents/skills && cp -r skills/portkill ~/.agents/skills/
```

Agents working on this repository should read [AGENTS.md](AGENTS.md).

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `-y`, `--yes` | off | Answer yes to the kill prompt. Does not imply SIGKILL. |
| `-f`, `--force` | off | Send SIGKILL without asking if the port is still busy after `--timeout`. |
| `--signal NAME` | `TERM` | First signal: `TERM`, `INT`, `HUP`, `QUIT`, `USR1`, `USR2`, `KILL` (name, `SIG` prefix or number). Windows: `TERM` or `KILL` only. |
| `--timeout DUR` | `5s` | How long to wait for the port to be released after each signal. |
| `--dry-run` | off | Show what would be signalled, change nothing. |
| `--udp` | off | Look at bound UDP sockets instead of listening TCP sockets. |
| `-l`, `--list` | off | List listeners (all, or only the given ports). |
| `--json` | off | Print JSON to stdout. Prompts, if any, go to stderr. |
| `--no-color` | off | Disable colour. `NO_COLOR` is honoured; colour is only used on a terminal. |
| `--mcp` | off | Run an MCP server on stdio for AI agents (see above). Other flags and ports are ignored. |
| `--allow-destructive` | off | With `--mcp`, also offer `portkill_kill`, which kills without a prompt. |
| `--version` | | Print the version. |
| `-h`, `--help` | | Show help with examples. |

Flags may come before or after the ports. Ports can be single (`3000`), ranges
(`8000-8010`) or comma lists (`3000,5173`).

## JSON

`portkill --json --dry-run 3000`:

```json
{
  "ports": [
    {
      "port": 3000,
      "proto": "tcp",
      "listening": true,
      "processes": [
        {
          "pid": 36969,
          "name": "node",
          "ppid": 1,
          "parent_name": "launchd",
          "user": "jordan",
          "cmd": "node server.js 3000",
          "cwd": "/private/tmp/my-app",
          "started": "2026-09-17T15:59:17Z",
          "uptime_seconds": 11,
          "addresses": [
            "*:3000"
          ],
          "killable": true
        }
      ],
      "result": "dry_run"
    }
  ],
  "exit_code": 0
}
```

Per port, `result` is one of `freed`, `not_listening`, `dry_run`, `declined`,
`refused`, `still_listening`, `error`, with a human readable `message` when
there is something to explain. Per process, optional fields are omitted when
unknown: `ppid`, `parent_name`, `user`, `cmd`, `cwd`, `started` (RFC 3339,
UTC), `uptime_seconds`. Also optional: `refusal` (why it will not be killed),
`docker` (`{"containers": [...], "hint": "docker stop web"}`),
`signals_sent` (for example `["TERM", "KILL"]`) and `signal_error`. A
listener whose owner is not visible has `"pid": 0`.

`portkill --list --json` prints
`{"listeners": [{"port", "proto", "pid", "name", "user", "addresses"}]}`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every port that had a listener was freed (also: `--dry-run` found something to kill, `--list` found listeners). |
| 1 | Nothing was listening on any of the given ports. |
| 2 | Error: discovery or signalling failed, or the port is still busy afterwards (survived SIGKILL, or a restarted process took it again). |
| 3 | Declined at the prompt, refused for safety, not a terminal without `--yes`, SIGKILL needed but not confirmed, or needs more privilege. |

With several ports the most serious outcome wins: 2, then 3, then 0, then 1.

## How it finds listeners

- **macOS**: `lsof -nP -F pcLPn -iTCP:<ports> -sTCP:LISTEN` (field output, not
  column scraping), merged with `netstat -anv`, which reports the PID of
  sockets owned by other users that an unprivileged lsof cannot see. Details
  come from `ps -o` and `lsof -d cwd`.
- **Linux**: `/proc/net/tcp` and `tcp6` (or `udp`, `udp6`), LISTEN state
  `0A`, with socket inodes matched against `/proc/*/fd` links. If some owners
  are unreadable, it falls back to `ss -lntp`, then `lsof`. Details come from
  `/proc/<pid>/stat`, `status`, `cmdline` and `cwd`.
- **Windows**: `netstat -ano -p TCP` and `TCPv6`, names from `tasklist /FO CSV`,
  and parent, command line, owner and start time from a `Win32_Process` CIM
  query. Listening rows are detected by a foreign port of 0, not by the word
  LISTENING, so non-English Windows works.

After a kill, the port is checked again with the same discovery plus a TCP
connect to 127.0.0.1 and ::1, so a listener that is still there but invisible
to you is not reported as freed.

## Limitations

- Without root, macOS and Linux do not show the working directory or full
  details of other users' processes, and on Linux the owning PID of their
  sockets may be unknown. portkill says so and suggests sudo; it does not
  guess.
- On macOS, a process name that only netstat could see is cut to 16
  characters.
- On Linux, start times assume a clock tick of 100 Hz, which is the value on
  mainstream kernels.
- On Windows the working directory is not shown. `taskkill` without `/F` only
  closes processes that have a window; console and background processes need
  `--force` (or a yes at the SIGKILL prompt). Error classification relies on
  English `taskkill` messages. Windows support is covered by CI but has had less
  real use than macOS and Linux.
- Docker is recognised by process name. Podman, Colima, Rancher Desktop and
  Lima forward ports through other processes (`gvproxy`, `ssh`, `limactl`),
  which portkill treats as ordinary processes.
- If a supervisor (systemd, launchd, pm2, nodemon, a shell loop) restarts the
  process, portkill reports that the port was taken again. It does not stop
  the supervisor.
- Command lines are printed with values of flags like `--password`, `--token`,
  `--api-key` and passwords in URLs masked. This is a heuristic; a secret
  passed as a plain positional argument will still be shown.
- There is a window between discovery and the signal (including the time you
  spend at the prompt) in which a process could exit and its PID be reused.
  portkill re-checks right before signalling that each PID is still listening
  on the port, which narrows the window to milliseconds but cannot close it.

## License

MIT
