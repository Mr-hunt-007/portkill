---
name: portkill
description: Find which process is listening on a local port and stop it safely with the portkill CLI. Use when a dev server fails with "address already in use" or EADDRINUSE, when asked what is running on a port, or when asked to free or kill whatever holds a port.
---

# portkill

portkill shows who holds a TCP or UDP port (PID, name, user, parent, working
directory, command line with secrets masked, uptime) and stops it safely. It
refuses PID 1, its own parent (your shell or agent), other users' processes,
and Docker's port forwarder, and it verifies the port is free afterwards.

## When to use

- A server cannot start because its port is taken.
- The user asks what is running on a port, or which ports are in use.
- The user asks to free a port or kill the process on it.

Do not kill anything the user did not ask you to stop. Inspect first.

## Commands

Inspect, change nothing:

```
portkill --dry-run --json 3000
portkill --dry-run --json 3000 5173 8000-8010
```

List all listeners:

```
portkill --list --json
```

Kill (only when asked). `--yes` is required because your stdin is not a
terminal; `--force` also allows SIGKILL if SIGTERM does not free the port:

```
portkill --yes --json 3000
portkill --yes --force --timeout 3s --json 3000
```

Use `--udp` for UDP ports.

## Reading the output

`{"ports": [...], "exit_code": N}`, one entry per port:

- `result`: `dry_run` (something killable), `not_listening`, `refused`,
  `freed` (verified free), `declined` (ignored SIGTERM, no `--force`),
  `still_listening` (survived, or a supervisor restarted it; see `message`),
  `error`.
- `processes[]`: `pid`, `name`, `user`, `cmd`, `cwd`, `ppid`,
  `parent_name`, `uptime_seconds`, `addresses`, `killable`, and `refusal`
  when it will not be killed. `pid` 0 means the owner is not visible
  without sudo.
- `docker`: when present, the listener is Docker's port forwarder. Run
  `docker.hint` (for example `docker stop web`) instead of killing.

`--list --json` gives `{"listeners": [{"port", "proto", "pid", "name", "user", "addresses"}]}`.

## Exit codes

- 0: freed, or `--dry-run` / `--list` found something
- 1: nothing listening
- 2: error, or the port is still busy afterwards
- 3: refused for safety, declined, or needs sudo

## Safety notes

- Check `cwd` and `cmd` to make sure the process belongs to the user's
  project before killing it.
- If the result is `still_listening` with a new PID, a supervisor (nodemon,
  pm2, systemd, launchd) restarted it; stop the supervisor instead of
  killing again.
- Do not retry with sudo on your own; tell the user.
- MCP alternative: `portkill --mcp` offers `portkill_inspect` and
  `portkill_list`; `portkill_kill` needs `--allow-destructive`.
