# ShellGate

An auditable SSH gateway for AI agents and MCP clients.

ShellGate exposes four Streamable HTTP MCP tools: `ssh_hosts` lists the
configured aliases and `ssh_exec` runs a non-interactive command against one or
more of them concurrently. Pass `hosts` to target multiple aliases; its result
contains one independently successful or failed result per host. The legacy
single `host` parameter remains supported. Batch results also include
`hosts_requested`, `hosts_ok`, `hosts_failed`, `failed`, and an overall
`status` of `ok`, `partial`, or `all_failed`.
`ssh_exec_script` uploads a complete POSIX shell script into a private random
temporary directory on every requested host, executes it using `/bin/sh -e`,
then removes the directory. Script text is not interpolated into a remote
command line.
Its audit record contains only the script SHA-256 and byte count by default;
set `audit.record_script_content: true` only when full script logging is
required.
The caller can never supply an address, SSH user, private key, or known-hosts
path.

## Quick start

```bash
go build -o shellgate ./cmd/shellgate
./shellgate init
# Edit ~/.local/share/shellgate/config.yaml and add hosts.
./shellgate check
./shellgate
```

State defaults to `$XDG_DATA_HOME/shellgate`, falling back to
`~/.local/share/shellgate`. Override it for every command with `--data-dir` or
`SHELLGATE_DATA_DIR`. The generated execution and log-reader MCP tokens are in
`mcp_token` and `mcp_log_token`; their values are never printed by the service.

The server listens on `127.0.0.1:8765` by default, requires
`Authorization: Bearer <token>`, and rejects every request carrying an
`Origin` header. `mcp_token` grants the SSH tools only; `mcp_log_token` grants
only read-only `audit_query`. It searches every audit-record field with plain
substring or Glob matching (`*` and `?`) and returns opaque pagination cursors.
Use local-time `from` and `to` values in `YYYYMMDDHHMMSS` format, or the
relative `time_range` presets `today`, `yesterday`, `last_1h`, `last_24h`, or
`last_7d`.
See [examples/config.yaml](examples/config.yaml) and
[deploy/shellgate.service](deploy/shellgate.service).

Command audit is JSONL under `logs/YYYY-MM-DD/<host>.jsonl`. A durable
`command` record is appended and synced before ShellGate begins remote
execution; a matching `result` or `error` record follows.
