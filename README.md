# ShellGate

An auditable SSH gateway for AI agents and MCP clients.

ShellGate exposes exactly two Streamable HTTP MCP tools: `ssh_hosts` lists the
configured aliases and `ssh_exec` runs a non-interactive command against one.
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
`SHELLGATE_DATA_DIR`. The generated MCP token is in `mcp_token` and is never
printed by the service.

The server listens on `127.0.0.1:8765` by default, requires
`Authorization: Bearer <token>`, and rejects every request carrying an
`Origin` header. See [examples/config.yaml](examples/config.yaml) and
[deploy/shellgate.service](deploy/shellgate.service).

Command audit is JSONL under `logs/YYYY-MM-DD/<host>.jsonl`. A durable
`command` record is appended and synced before ShellGate begins remote
execution; a matching `result` or `error` record follows.
