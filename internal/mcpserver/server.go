package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/zjyl1994/shellgate/internal/auth"
	"github.com/zjyl1994/shellgate/internal/broker"
	"github.com/zjyl1994/shellgate/internal/hosts"
)

type execInput struct {
	Host    string `json:"host" jsonschema:"managed host alias"`
	Command string `json:"command" jsonschema:"non-interactive remote command"`
}
type hostsOutput struct {
	Hosts []hosts.Info `json:"hosts"`
}

func Handler(reg *hosts.Registry, b *broker.Broker, authEnabled bool, token string) http.Handler {
	s := mcp.NewServer(&mcp.Implementation{Name: "ShellGate", Version: "0.1.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{Name: "ssh_hosts", Description: "List managed SSH hosts available to this agent."}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, hostsOutput, error) {
		return nil, hostsOutput{Hosts: reg.List()}, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "ssh_exec", Description: "Run a non-interactive command on a managed host. Use ssh_hosts when the target host is unknown. For long-running work, use remote background facilities such as systemd-run."}, func(ctx context.Context, _ *mcp.CallToolRequest, in execInput) (*mcp.CallToolResult, broker.Result, error) {
		res := b.Exec(ctx, in.Host, in.Command)
		if res.Error != "" {
			raw, _ := json.Marshal(res)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}}, IsError: true}, res, nil
		}
		return nil, res, nil
	})
	return auth.Middleware(authEnabled, token, mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
}
