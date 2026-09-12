package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zjyl1994/shellgate/internal/audit"
	"github.com/zjyl1994/shellgate/internal/auth"
	"github.com/zjyl1994/shellgate/internal/broker"
	"github.com/zjyl1994/shellgate/internal/hosts"
)

type execInput struct {
	// Host is retained for compatibility with existing single-host clients.
	Host    string   `json:"host,omitempty" jsonschema:"managed host alias (deprecated; use hosts)"`
	Hosts   []string `json:"hosts,omitempty" jsonschema:"managed host aliases; runs the command concurrently on each host"`
	Command string   `json:"command" jsonschema:"non-interactive remote command"`
}
type scriptInput struct {
	Hosts  []string `json:"hosts" jsonschema:"managed host aliases; runs the script concurrently on each host"`
	Script string   `json:"script" jsonschema:"complete POSIX shell script; uploaded without command-line interpolation"`
}
type hostsOutput struct {
	Hosts []hosts.Info `json:"hosts"`
}
type auditQueryInput struct {
	Hosts     []string      `json:"hosts,omitempty" jsonschema:"managed host aliases; omit to search all managed hosts"`
	From      string        `json:"from,omitempty" jsonschema:"inclusive local timestamp in YYYYMMDDHHMMSS; required unless time_range is set"`
	To        string        `json:"to,omitempty" jsonschema:"inclusive local timestamp in YYYYMMDDHHMMSS; required unless time_range is set"`
	TimeRange string        `json:"time_range,omitempty" jsonschema:"preset: today, yesterday, last_1h, last_24h, or last_7d; mutually exclusive with from and to"`
	Events    []string      `json:"events,omitempty" jsonschema:"optional audit event names to include"`
	Search    *audit.Search `json:"search,omitempty" jsonschema:"optional full-record text search; mode is substring or glob"`
	Limit     int           `json:"limit,omitempty" jsonschema:"result count from 1 to 1000; default 100"`
	Cursor    string        `json:"cursor,omitempty" jsonschema:"opaque cursor from a preceding audit_query result"`
}

// Version changes whenever the MCP tool surface or schemas change so clients
// can invalidate cached tool metadata.
const Version = "0.2.3"

func Handler(reg *hosts.Registry, b *broker.Broker, auditDir string, authEnabled bool, token, logToken string) http.Handler {
	execServer := mcp.NewServer(&mcp.Implementation{Name: "ShellGate", Version: Version}, nil)
	logServer := mcp.NewServer(&mcp.Implementation{Name: "ShellGate Logs", Version: Version}, nil)
	s := execServer
	mcp.AddTool(s, &mcp.Tool{Name: "ssh_hosts", Description: "List managed SSH hosts available to this agent."}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, hostsOutput, error) {
		return nil, hostsOutput{Hosts: reg.List()}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "ssh_exec", Description: "Run the same non-interactive command on one or more managed hosts. Provide hosts to run concurrently (preferred), or host for a legacy single-host call. The result always identifies each host's success or failure. Use ssh_hosts when target aliases are unknown. For long-running work, use remote background facilities such as systemd-run."}, func(ctx context.Context, _ *mcp.CallToolRequest, in execInput) (*mcp.CallToolResult, broker.BatchResult, error) {
		names := in.Hosts
		if len(names) == 0 && in.Host != "" {
			names = []string{in.Host}
		}
		if len(names) == 0 {
			res := broker.BatchResult{
				Results:     []broker.HostResult{{Result: broker.Result{Error: "missing_hosts"}}},
				HostsFailed: 1,
				Failed:      []string{""},
				Status:      "all_failed",
			}
			raw, _ := json.Marshal(res)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
		}

		res := b.ExecMany(ctx, names, in.Command)
		for _, host := range res.Results {
			if !host.OK {
				raw, _ := json.Marshal(res)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
			}
		}
		return nil, res, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "ssh_exec_script", Description: "Upload and run the same complete POSIX shell script concurrently on managed hosts. The script is written in a private random temporary directory and executed with /bin/sh -e, avoiding shell-quoting of the script text. The directory is removed after execution. The result always identifies each host's success or failure."}, func(ctx context.Context, _ *mcp.CallToolRequest, in scriptInput) (*mcp.CallToolResult, broker.BatchResult, error) {
		if len(in.Hosts) == 0 {
			res := broker.BatchResult{Results: []broker.HostResult{{Result: broker.Result{Error: "missing_hosts"}}}, HostsFailed: 1, Failed: []string{""}, Status: "all_failed"}
			raw, _ := json.Marshal(res)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
		}
		res := b.ExecManyScript(ctx, in.Hosts, in.Script)
		for _, host := range res.Results {
			if !host.OK {
				raw, _ := json.Marshal(res)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
			}
		}
		return nil, res, nil
	})
	mcp.AddTool(logServer, &mcp.Tool{Name: "audit_query", Description: "Read and search complete ShellGate audit records. Search scans every field in matching records using substring or glob (* and ?; use \\ to escape either). Results are paginated and never execute remote commands. When next_cursor is returned, repeat the identical query with that exact value in cursor; do not change any other filter."}, func(_ context.Context, _ *mcp.CallToolRequest, in auditQueryInput) (*mcp.CallToolResult, audit.QueryResult, error) {
		names := in.Hosts
		if len(names) == 0 {
			for _, host := range reg.List() {
				names = append(names, host.Name)
			}
		}
		for _, name := range names {
			if _, ok := reg.Get(name); !ok {
				res := audit.QueryResult{}
				raw, _ := json.Marshal(map[string]string{"error": "unknown_host", "host": name})
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
			}
		}
		res, err := audit.QueryLogs(auditDir, audit.Query{Hosts: names, From: in.From, To: in.To, TimeRange: in.TimeRange, Events: in.Events, Search: in.Search, Limit: in.Limit, Cursor: in.Cursor}, []byte(logToken))
		if err != nil {
			raw, _ := json.Marshal(map[string]string{"error": "invalid_query", "message": err.Error()})
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, audit.QueryResult{}, nil
		}
		return nil, res, nil
	})
	return auth.Middleware(authEnabled, token, logToken, mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		if auth.RoleFromContext(r.Context()) == auth.LogReaderRole {
			return logServer
		}
		return execServer
	}, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
}
