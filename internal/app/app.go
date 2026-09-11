package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/zjyl1994/shellgate/internal/audit"
	"github.com/zjyl1994/shellgate/internal/broker"
	"github.com/zjyl1994/shellgate/internal/config"
	"github.com/zjyl1994/shellgate/internal/hosts"
)

func Init(dataDir string) error {
	if e := config.Init(dataDir); e != nil {
		return e
	}
	fmt.Printf("ShellGate initialized.\n\nData directory:\n  %s\n\nConfig:\n  %s\n\nMCP execution token:\n  %s\n\nMCP log-reader token:\n  %s\n\nSSH keys:\n  %s\n\nAudit logs:\n  %s\n\nEdit config.yaml and start ShellGate again.\n", dataDir, filepath.Join(dataDir, "config.yaml"), filepath.Join(dataDir, "mcp_token"), filepath.Join(dataDir, "mcp_log_token"), filepath.Join(dataDir, "keys"), filepath.Join(dataDir, "logs"))
	return nil
}
func Check(dataDir string) error {
	_, e := config.Load(dataDir)
	if e == nil {
		fmt.Println("ShellGate configuration is valid.")
	}
	return e
}
func Serve(dataDir string, handler func(*hosts.Registry, *broker.Broker, string, bool, string, string) http.Handler) error {
	r, e := config.Load(dataDir)
	if e != nil {
		return e
	}
	reg := hosts.New(r.Hosts)
	b := broker.New(reg, audit.New(r.AuditDir, r.Config.Audit.FilenameTemplate, r.Config.Audit.OutputLimit, r.Config.Audit.RecordScriptContent), r)
	defer b.Close()
	srv := &http.Server{
		Addr:              r.Config.MCP.Listen,
		Handler:           handler(reg, b, r.AuditDir, r.Config.MCP.Auth.Enabled, r.Token, r.LogToken),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      r.CommandTimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); _ = srv.Shutdown(context.Background()) }()
	fmt.Fprintf(os.Stderr, "ShellGate listening on %s\n", srv.Addr)
	e = srv.ListenAndServe()
	if e == http.ErrServerClosed {
		return nil
	}
	return e
}
