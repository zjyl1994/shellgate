package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/melbahja/goph/v2"
	"github.com/zjyl1994/shellgate/internal/audit"
	"github.com/zjyl1994/shellgate/internal/config"
	"github.com/zjyl1994/shellgate/internal/hosts"
	"golang.org/x/crypto/ssh"
)

type Result struct {
	OK           bool   `json:"ok"`
	ExitCode     *int   `json:"exit_code,omitempty"`
	Output       string `json:"output,omitempty"`
	Truncated    bool   `json:"truncated"`
	DurationMS   int64  `json:"duration_ms"`
	Error        string `json:"error,omitempty"`
	CleanupError string `json:"cleanup_error,omitempty"`
}

// HostResult associates an execution result with the managed host it was run
// on. A result is returned for every requested host, including hosts that
// could not be reached or are not configured.
type HostResult struct {
	Host string `json:"host"`
	Result
}

// BatchResult is the result of running one command on multiple managed hosts.
// Results keep the requested-host order even though execution is concurrent.
type BatchResult struct {
	Results        []HostResult `json:"results"`
	HostsRequested int          `json:"hosts_requested"`
	HostsOK        int          `json:"hosts_ok"`
	HostsFailed    int          `json:"hosts_failed"`
	Failed         []string     `json:"failed"`
	Status         string       `json:"status"`
}
type managed struct {
	mu       sync.Mutex
	client   *goph.Client
	lastUsed time.Time
}
type Broker struct {
	reg                    *hosts.Registry
	audit                  *audit.Writer
	clients                map[string]*managed
	clientsMu              sync.Mutex
	connect, command, idle time.Duration
	aiLimit                int
	closed                 chan struct{}
}

func New(r *hosts.Registry, a *audit.Writer, c *config.Runtime) *Broker {
	b := &Broker{reg: r, audit: a, clients: map[string]*managed{}, connect: c.ConnectTimeout, command: c.CommandTimeout, idle: c.IdleTimeout, aiLimit: c.Config.MCP.AIOutputLimit, closed: make(chan struct{})}
	go b.reap()
	return b
}
func (b *Broker) Exec(ctx context.Context, name, command string) Result {
	h, ok := b.reg.Get(name)
	if !ok {
		return Result{Error: "unknown_host"}
	}
	id := requestID()
	if e := b.audit.Command(id, name, command); e != nil {
		return Result{Error: "internal_error"}
	}
	m := b.managed(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, b.command)
	defer cancel()
	if m.client == nil {
		c, code := b.dial(ctx, h)
		if code != "" {
			_ = b.audit.Error(id, name, "connect", code, "not_started")
			return Result{Error: code}
		}
		m.client = c
	}
	stdout, stderr := newTailBuffer(b.audit.OutputLimit()), newTailBuffer(b.audit.OutputLimit())
	cmd, e := m.client.CommandContext(ctx, command)
	if e == nil {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		e = cmd.Run()
	}
	d := time.Since(started)
	m.lastUsed = time.Now()
	if ctx.Err() != nil {
		m.client.Close()
		m.client = nil
		_ = b.audit.Error(id, name, "execute", "command_timeout", "unknown")
		return Result{Error: "command_timeout", DurationMS: d.Milliseconds()}
	}
	out, serr := b.audit.LimitTail(stdout.Bytes(), stdout.Total()), b.audit.LimitTail(stderr.Bytes(), stderr.Total())
	if e != nil {
		var xe *ssh.ExitError
		if errors.As(e, &xe) {
			x := xe.ExitStatus()
			_ = b.audit.Result(id, name, x, d, out, serr)
			joined := combine(out.Text, serr.Text)
			return Result{OK: false, ExitCode: &x, Output: limitOutput(joined, b.aiLimit), Truncated: out.Truncated || serr.Truncated || len(joined) > b.aiLimit, DurationMS: d.Milliseconds()}
		}
		m.client.Close()
		m.client = nil
		_ = b.audit.Error(id, name, "execute", "execution_state_unknown", "unknown")
		return Result{Error: "execution_state_unknown", DurationMS: d.Milliseconds()}
	}
	x := 0
	_ = b.audit.Result(id, name, x, d, out, serr)
	joined := combine(out.Text, serr.Text)
	return Result{OK: true, ExitCode: &x, Output: limitOutput(joined, b.aiLimit), Truncated: out.Truncated || serr.Truncated || len(joined) > b.aiLimit, DurationMS: d.Milliseconds()}
}

// ExecMany runs command concurrently on every named host. It deliberately
// waits for every execution so a failure on one host never hides the outcome
// from another host.
func (b *Broker) ExecMany(ctx context.Context, names []string, command string) BatchResult {
	results := make([]HostResult, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			results[i] = HostResult{Host: name, Result: b.Exec(ctx, name, command)}
		}(i, name)
	}
	wg.Wait()
	return summarizeBatch(results)
}

// ExecScript uploads script to a random private temporary directory on name,
// runs it with /bin/sh -se, and then removes the directory. Script text is
// never interpolated into a remote command line.
func (b *Broker) ExecScript(ctx context.Context, name, script string) Result {
	h, ok := b.reg.Get(name)
	if !ok {
		return Result{Error: "unknown_host"}
	}
	id := requestID()
	if e := b.audit.Script(id, name, script); e != nil {
		return Result{Error: "internal_error"}
	}
	m := b.managed(name)
	m.mu.Lock()
	defer m.mu.Unlock()
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, b.command)
	defer cancel()
	if m.client == nil {
		c, code := b.dial(ctx, h)
		if code != "" {
			_ = b.audit.Error(id, name, "connect", code, "not_started")
			return Result{Error: code}
		}
		m.client = c
	}
	remoteDir := fmt.Sprintf("/tmp/shellgate-%s", id)
	remotePath := remoteDir + "/script.sh"
	if e := makeScriptDir(ctx, m.client, remoteDir); e != nil {
		m.client.Close()
		m.client = nil
		code := "script_upload_failed"
		if ctx.Err() != nil {
			code = "command_timeout"
		}
		_ = b.audit.Error(id, name, "upload", code, "not_started")
		return Result{Error: code, DurationMS: time.Since(started).Milliseconds()}
	}
	if e := writeScript(ctx, m.client, remotePath, script); e != nil {
		_ = removeScript(ctx, m.client, remotePath, remoteDir)
		m.client.Close()
		m.client = nil
		code := "script_upload_failed"
		if ctx.Err() != nil {
			code = "command_timeout"
		}
		_ = b.audit.Error(id, name, "upload", code, "not_started")
		return Result{Error: code, DurationMS: time.Since(started).Milliseconds()}
	}

	stdout, stderr := newTailBuffer(b.audit.OutputLimit()), newTailBuffer(b.audit.OutputLimit())
	cmd, e := m.client.CommandContext(ctx, "/bin/sh", "-se", remotePath)
	if e == nil {
		cmd.Stdout = stdout
		cmd.Stderr = stderr
		e = cmd.Run()
	}
	d := time.Since(started)
	m.lastUsed = time.Now()
	cleanupErr := removeScript(ctx, m.client, remotePath, remoteDir)
	if cleanupErr != nil {
		_ = b.audit.Error(id, name, "cleanup", "script_cleanup_failed", "unknown")
	}
	if ctx.Err() != nil {
		m.client.Close()
		m.client = nil
		_ = b.audit.Error(id, name, "execute", "command_timeout", "unknown")
		return Result{Error: "command_timeout", DurationMS: d.Milliseconds(), CleanupError: errorCode(cleanupErr)}
	}
	out, serr := b.audit.LimitTail(stdout.Bytes(), stdout.Total()), b.audit.LimitTail(stderr.Bytes(), stderr.Total())
	if e != nil {
		var xe *ssh.ExitError
		if errors.As(e, &xe) {
			x := xe.ExitStatus()
			_ = b.audit.Result(id, name, x, d, out, serr)
			joined := combine(out.Text, serr.Text)
			return Result{OK: false, ExitCode: &x, Output: limitOutput(joined, b.aiLimit), Truncated: out.Truncated || serr.Truncated || len(joined) > b.aiLimit, DurationMS: d.Milliseconds(), CleanupError: errorCode(cleanupErr)}
		}
		m.client.Close()
		m.client = nil
		_ = b.audit.Error(id, name, "execute", "execution_state_unknown", "unknown")
		return Result{Error: "execution_state_unknown", DurationMS: d.Milliseconds(), CleanupError: errorCode(cleanupErr)}
	}
	if cleanupErr != nil {
		x := 0
		joined := combine(out.Text, serr.Text)
		return Result{ExitCode: &x, Output: limitOutput(joined, b.aiLimit), Truncated: out.Truncated || serr.Truncated || len(joined) > b.aiLimit, DurationMS: d.Milliseconds(), Error: "script_cleanup_failed", CleanupError: "script_cleanup_failed"}
	}
	x := 0
	_ = b.audit.Result(id, name, x, d, out, serr)
	joined := combine(out.Text, serr.Text)
	return Result{OK: true, ExitCode: &x, Output: limitOutput(joined, b.aiLimit), Truncated: out.Truncated || serr.Truncated || len(joined) > b.aiLimit, DurationMS: d.Milliseconds()}
}

// ExecManyScript runs the same script concurrently on every named host.
func (b *Broker) ExecManyScript(ctx context.Context, names []string, script string) BatchResult {
	results := make([]HostResult, len(names))
	var wg sync.WaitGroup
	for i, name := range names {
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			results[i] = HostResult{Host: name, Result: b.ExecScript(ctx, name, script)}
		}(i, name)
	}
	wg.Wait()
	return summarizeBatch(results)
}

func writeScript(ctx context.Context, c *goph.Client, path, script string) error {
	return withSFTPContext(ctx, c, func() error {
		ftp, err := c.NewSftp()
		if err != nil {
			return err
		}
		defer ftp.Close()
		f, err := ftp.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
		if err != nil {
			return err
		}
		if _, err = f.Write([]byte(script)); err == nil {
			err = f.Chmod(0700)
		}
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		return err
	})
}

func makeScriptDir(ctx context.Context, c *goph.Client, dir string) error {
	cmd, err := c.CommandContext(ctx, "mkdir", "-m", "700", dir)
	if err != nil {
		return err
	}
	return cmd.Run()
}

func removeScript(ctx context.Context, c *goph.Client, path, dir string) error {
	return withSFTPContext(ctx, c, func() error {
		ftp, err := c.NewSftp()
		if err != nil {
			return err
		}
		defer ftp.Close()
		if err = ftp.Remove(path); err != nil {
			return err
		}
		return ftp.RemoveDirectory(dir)
	})
}

func withSFTPContext(ctx context.Context, c *goph.Client, operation func() error) error {
	done := make(chan error, 1)
	go func() { done <- operation() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		// SFTP has no context-aware API. Closing its SSH transport unblocks the
		// in-flight operation and prevents a timed-out upload from continuing.
		_ = c.Close()
		return ctx.Err()
	}
}

func errorCode(err error) string {
	if err != nil {
		return "script_cleanup_failed"
	}
	return ""
}

func summarizeBatch(results []HostResult) BatchResult {
	batch := BatchResult{
		Results:        results,
		HostsRequested: len(results),
		Failed:         make([]string, 0),
	}
	for _, result := range results {
		if result.OK {
			batch.HostsOK++
			continue
		}
		batch.HostsFailed++
		batch.Failed = append(batch.Failed, result.Host)
	}
	switch {
	case batch.HostsFailed == 0:
		batch.Status = "ok"
	case batch.HostsOK == 0:
		batch.Status = "all_failed"
	default:
		batch.Status = "partial"
	}
	return batch
}
func (b *Broker) managed(n string) *managed {
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	if b.clients[n] == nil {
		b.clients[n] = &managed{}
	}
	return b.clients[n]
}
func (b *Broker) dial(ctx context.Context, h config.RuntimeHost) (*goph.Client, string) {
	done := make(chan struct{})
	var c *goph.Client
	var e error
	go func() {
		c, e = goph.New(h.User, h.Address, goph.WithPort(h.Port), goph.WithKeyFile(h.PrivateKeyFile, ""), goph.WithKnownHosts(h.KnownHostsFile), goph.WithTimeout(b.connect))
		close(done)
	}()
	select {
	case <-done:
		if e == nil {
			return c, ""
		}
		return nil, classifyConnect(e)
	case <-ctx.Done():
		// goph.New cannot consume a context. If it wins the race later, close
		// the resulting client instead of leaking an authenticated connection.
		go func() {
			<-done
			if c != nil {
				_ = c.Close()
			}
		}()
		return nil, "connect_timeout"
	}
}

func classifyConnect(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &ne) && ne.Timeout() {
		return "connect_timeout"
	}
	// goph delegates strict verification to x/crypto/ssh/knownhosts. Its
	// concrete error is intentionally not exposed to MCP callers.
	s := strings.ToLower(err.Error())
	if strings.Contains(s, "knownhost") || strings.Contains(s, "known host") || strings.Contains(s, "key mismatch") {
		return "host_key_failed"
	}
	return "connect_failed"
}
func (b *Broker) reap() {
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-b.closed:
			return
		case <-tick.C:
			b.clientsMu.Lock()
			for _, m := range b.clients {
				if m.mu.TryLock() {
					if m.client != nil && time.Since(m.lastUsed) > b.idle {
						m.client.Close()
						m.client = nil
					}
					m.mu.Unlock()
				}
			}
			b.clientsMu.Unlock()
		}
	}
}
func (b *Broker) Close() {
	close(b.closed)
	b.clientsMu.Lock()
	defer b.clientsMu.Unlock()
	for _, m := range b.clients {
		m.mu.Lock()
		if m.client != nil {
			m.client.Close()
		}
		m.mu.Unlock()
	}
}
func requestID() string { b := make([]byte, 8); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func combine(a, s string) string {
	if s == "" {
		return a
	}
	if a == "" {
		return "[stderr]\n" + s
	}
	return a + "\n[stderr]\n" + s
}
func limitOutput(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return string([]byte(s)[len(s)-n:])
}

// tailBuffer bounds memory while retaining the newest output for auditing.
type tailBuffer struct {
	buf   []byte
	total int
	limit int
}

func newTailBuffer(limit int) *tailBuffer { return &tailBuffer{limit: limit} }

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.total += len(p)
	if b.limit <= 0 {
		return len(p), nil
	}
	if len(p) >= b.limit {
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		return len(p), nil
	}
	if excess := len(b.buf) + len(p) - b.limit; excess > 0 {
		copy(b.buf, b.buf[excess:])
		b.buf = b.buf[:len(b.buf)-excess]
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *tailBuffer) Bytes() []byte { return b.buf }
func (b *tailBuffer) Total() int    { return b.total }
