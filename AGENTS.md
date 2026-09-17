# AGENTS.md

## What this is

portkill is a Go CLI that shows what is listening on a TCP or UDP port
(PID, name, user, parent, working directory, masked command line, uptime)
and stops it safely: it refuses dangerous targets, waits for the port to be
released, escalates to SIGKILL only when allowed, and verifies the port is
free. macOS, Linux and Windows. It also runs as an MCP server (`--mcp`).

## Layout

- `main.go`: wires the real OS (`sys.OS`), stdio and the MCP server into `app.Run`.
- `internal/app`: argument parsing, the discover, show, confirm, signal,
  verify flow, safety refusals, rendering, JSON types (`Report`,
  `ListReport`), and `api.go` (`Inspect`, `List`, `KillPID`), the
  non-interactive entry points used by the MCP tools. All OS access goes
  through the `System` interface, so tests use a fake.
- `internal/parse`: pure parsers for lsof, netstat, `/proc/net`, ss, ps,
  tasklist and docker output, port arguments, command line masking. No I/O.
- `internal/sys`: the thin OS boundary (runs commands, reads `/proc`, sends
  signals, TTY detection). Integration tests start real listener processes.
- `internal/mcp`: a small stdlib MCP server (JSON-RPC over stdio). Shared
  with the other tools; do not change it here alone.
- `internal/mcptools`: the MCP tools `portkill_inspect`, `portkill_list`
  and, with `--allow-destructive`, `portkill_kill`.
- `skills/portkill/SKILL.md`: Agent Skill for using the CLI.

## Build and test (as CI runs them)

```
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
go build .
```

CI runs these on ubuntu-latest, macos-latest and windows-latest.

## Rules for contributors

- Go standard library only. No third-party modules. `go 1.22` in `go.mod`.
- gofmt, vet and `go test -race ./...` must pass on all three OSes. Skip
  OS-specific tests with a reason instead of letting them fail.
- Tests use real fixtures: table-driven parser tests on captured output,
  fake `System` tests for the flow, and real listener processes for
  integration. After changing behaviour, run the built binary against real
  listeners (for example `python3 -m http.server 48000`) and read the output.
- README terminal output is pasted from real runs, never typed by hand.
- No em dashes (U+2014) anywhere. En dashes only in numeric ranges.
- The `--json` shapes and the exit codes are a compatibility contract. Only
  add optional fields; never rename or remove one. MCP tools return the same
  JSON as the matching CLI command.
- Safety checks live in `internal/app` (`classify`) and apply to every entry
  point. Never add a path that signals a process without them.
- MCP handlers must never write to stdout, call `os.Exit` or change the
  working directory. Destructive tools are registered only with
  `--allow-destructive`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Every port that had a listener was freed (or `--dry-run` / `--list` found something). |
| 1 | Nothing was listening on any given port. |
| 2 | Error, or the port is still busy afterwards. |
| 3 | Declined, refused for safety, not a terminal without `--yes`, or needs more privilege. |

## Using portkill as an agent

- Inspect without side effects: `portkill --dry-run --json 3000`. Read
  `ports[].result` and `ports[].processes[]` (`pid`, `killable`, `refusal`,
  `docker.hint`).
- List listeners: `portkill --list --json`.
- Kill only when the user asked for it: `portkill --yes --json 3000`
  (add `--force` to allow SIGKILL). stdin is not a terminal for an agent,
  so without `--yes` portkill refuses with exit code 3.
- If `docker` is present, run its `hint` (`docker stop <name>`) instead.
- MCP: `portkill --mcp` (read-only tools), `portkill --mcp --allow-destructive`
  (adds `portkill_kill`, which needs the PID from `portkill_inspect`).
