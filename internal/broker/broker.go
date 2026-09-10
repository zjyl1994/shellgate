package broker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
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
	OK         bool   `json:"ok"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	Output     string `json:"output,omitempty"`
	Truncated  bool   `json:"truncated"`
	DurationMS int64  `json:"duration_ms"`
	Error      string `json:"error,omitempty"`
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
