# Changelog

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
