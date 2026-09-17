# Changelog

## 0.2.0 (2026-09-17)

- `portkill --mcp` runs an MCP server on stdio with two read-only tools:
  `portkill_inspect` (the `--dry-run --json` report for given ports) and
  `portkill_list` (the `--list --json` listing, capped by `limit`).
- `portkill --mcp --allow-destructive` adds `portkill_kill`, which stops one
  PID on one port without a prompt. It does nothing unless that PID is
  listening on the port at call time, applies every CLI refusal, sends
  SIGKILL only with `force`, and verifies the port afterwards.
- `AGENTS.md`, `CLAUDE.md`, `llms.txt` and an Agent Skill in
  `skills/portkill`.
- The refusal message for portkill's parent process now also covers an
  agent that started portkill.

## 0.1.0 (2026-09-17)

First release.

- `portkill PORT...` shows every process listening on the given TCP ports
  (or UDP with `--udp`), with parent, user, command line, working directory
  and uptime, then asks before killing.
- Ports, comma lists and ranges (`3000 5173 8000-8010`). Several processes on
  one port (IPv4 and IPv6, forked workers) are shown once per PID.
- Kill flow: `--signal` (default TERM), wait up to `--timeout` for the port to
  free, offer SIGKILL (`--force` sends it without asking), then verify the
  port is really free and report a respawned listener if one appears.
- Safety: refuses PID 1, the Windows System process, portkill itself and its
  parent shell; refuses other users' processes unless run as root; points at
  `docker stop <container>` instead of killing Docker's port forwarder;
  refuses to act on a non-TTY stdin without `--yes`.
- `--list`, `--json`, `--dry-run`, `--no-color` / `NO_COLOR`.
- Discovery: lsof field output plus `netstat -anv` on macOS, `/proc/net` on
  Linux with `ss`/`lsof` fallback, `netstat -ano` plus `tasklist` and a CIM
  query on Windows.
- Command lines are shown with likely secrets (password, token, API key flags
  and URL passwords) masked.
