package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/melbahja/goph/v2"
	"github.com/zjyl1994/shellgate/internal/paths"
	"gopkg.in/yaml.v3"
)

const DefaultYAML = `ssh:
  private_key_file: "~/.ssh/id_ed25519"
  known_hosts_file: "~/.ssh/known_hosts"
  connect_timeout: "10s"
  command_timeout: "120s"
  idle_timeout: "60s"
hosts:
  # example-host:
  #   address: "192.0.2.10"
  #   port: 22
  #   user: "ops"
  #   private_key_file: "~/.ssh/id_ed25519" # optional: overrides ssh default
  #   known_hosts_file: "~/.ssh/known_hosts" # optional: overrides ssh default
  #   description: "Example managed host"
mcp:
  listen: "127.0.0.1:8765"
  ai_output_limit: 20000
  auth:
    enabled: true
    token: ""
    token_file: "mcp_token"
audit:
  directory: "logs"
  filename_template: "{host}.jsonl"
  output_limit: 524288
`

type Config struct {
	SSH   SSHConfig             `yaml:"ssh"`
	Hosts map[string]HostConfig `yaml:"hosts"`
	MCP   MCPConfig             `yaml:"mcp"`
	Audit AuditConfig           `yaml:"audit"`
}
type SSHConfig struct {
	PrivateKeyFile string `yaml:"private_key_file"`
	KnownHostsFile string `yaml:"known_hosts_file"`
	ConnectTimeout string `yaml:"connect_timeout"`
	CommandTimeout string `yaml:"command_timeout"`
	IdleTimeout    string `yaml:"idle_timeout"`
}
type HostConfig struct {
	Address        string `yaml:"address"`
	Port           uint   `yaml:"port,omitempty"`
	User           string `yaml:"user"`
	PrivateKeyFile string `yaml:"private_key_file,omitempty"`
	KnownHostsFile string `yaml:"known_hosts_file,omitempty"`
	Description    string `yaml:"description,omitempty"`
}
type MCPConfig struct {
	Listen        string     `yaml:"listen"`
	AIOutputLimit int        `yaml:"ai_output_limit"`
	Auth          AuthConfig `yaml:"auth"`
}
type AuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Token     string `yaml:"token,omitempty"`
	TokenFile string `yaml:"token_file,omitempty"`
}
type AuditConfig struct {
	Directory        string `yaml:"directory"`
	FilenameTemplate string `yaml:"filename_template"`
	OutputLimit      int    `yaml:"output_limit"`
}
type RuntimeHost struct {
	Name, Address, User, PrivateKeyFile, KnownHostsFile, Description string
	Port                                                             uint
}
type Runtime struct {
	Config                                      Config
	DataDir, Token, AuditDir                    string
	ConnectTimeout, CommandTimeout, IdleTimeout time.Duration
	Hosts                                       map[string]RuntimeHost
}

func Init(dataDir string) error {
	for _, d := range []string{dataDir, filepath.Join(dataDir, "keys"), filepath.Join(dataDir, "logs")} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return err
		}
	}
	cfg := filepath.Join(dataDir, "config.yaml")
	if _, err := os.Stat(cfg); errors.Is(err, os.ErrNotExist) {
		if err = os.WriteFile(cfg, []byte(DefaultYAML), 0600); err != nil {
			return err
		}
	}
	_, err := ensureToken(filepath.Join(dataDir, "mcp_token"))
	return err
}
func Load(dataDir string) (*Runtime, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, "config.yaml"))
	if err != nil {
		return nil, err
	}
	var c Config
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	r := &Runtime{Config: c, DataDir: dataDir, Hosts: map[string]RuntimeHost{}, AuditDir: paths.Resolve(dataDir, c.Audit.Directory)}
	var e error
	if r.ConnectTimeout, e = time.ParseDuration(c.SSH.ConnectTimeout); e != nil {
		return nil, e
	}
	if r.CommandTimeout, e = time.ParseDuration(c.SSH.CommandTimeout); e != nil {
		return nil, e
	}
	if r.IdleTimeout, e = time.ParseDuration(c.SSH.IdleTimeout); e != nil {
		return nil, e
	}
	if r.ConnectTimeout <= 0 || r.CommandTimeout <= 0 || r.IdleTimeout <= 0 || c.MCP.AIOutputLimit <= 0 || c.Audit.OutputLimit <= 0 {
		return nil, errors.New("timeouts and output limits must be positive")
	}
	if _, _, e = net.SplitHostPort(c.MCP.Listen); e != nil {
		return nil, fmt.Errorf("mcp.listen: %w", e)
	}
	if !c.MCP.Auth.Enabled && !isLoopback(c.MCP.Listen) {
		return nil, errors.New("authentication disabled requires loopback listen address")
	}
	if strings.Contains(c.Audit.FilenameTemplate, "/") || strings.Contains(c.Audit.FilenameTemplate, "\\") || strings.Contains(c.Audit.FilenameTemplate, "..") || !strings.Contains(c.Audit.FilenameTemplate, "{host}") {
		return nil, errors.New("invalid audit filename_template")
	}
	alias := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	for n, h := range c.Hosts {
		if !alias.MatchString(n) {
			return nil, fmt.Errorf("invalid host alias %q", n)
		}
		rh := RuntimeHost{Name: n, Address: h.Address, User: h.User, Port: h.Port, Description: h.Description, PrivateKeyFile: paths.Resolve(dataDir, choose(h.PrivateKeyFile, c.SSH.PrivateKeyFile)), KnownHostsFile: paths.Resolve(dataDir, choose(h.KnownHostsFile, c.SSH.KnownHostsFile))}
		if rh.Port == 0 {
			rh.Port = 22
		}
		if rh.Address == "" || rh.User == "" || rh.Port > 65535 {
			return nil, fmt.Errorf("invalid host %q", n)
		}
		if err := regularReadable(rh.PrivateKeyFile); err != nil {
			return nil, fmt.Errorf("host %s private key: %w", n, err)
		}
		if _, err := goph.ParseKeyFile(rh.PrivateKeyFile, ""); err != nil {
			return nil, fmt.Errorf("host %s private key: %w", n, err)
		}
		if err := regularReadable(rh.KnownHostsFile); err != nil {
			return nil, fmt.Errorf("host %s known hosts: %w", n, err)
		}
		r.Hosts[n] = rh
	}
	if c.MCP.Auth.Enabled {
		if c.MCP.Auth.Token != "" {
			r.Token = c.MCP.Auth.Token
		} else {
			p := paths.Resolve(dataDir, c.MCP.Auth.TokenFile)
			if p == "" {
				return nil, errors.New("token_file required")
			}
			r.Token, e = ensureToken(p)
			if e != nil {
				return nil, e
			}
		}
	}
	return r, nil
}
func choose(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
func regularReadable(p string) error {
	s, e := os.Stat(p)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	f, e := os.Open(p)
	if e == nil {
		e = f.Close()
	}
	return e
}
func ensureToken(p string) (string, error) {
	b, e := os.ReadFile(p)
	if e == nil && strings.TrimSpace(string(b)) != "" {
		return strings.TrimSpace(string(b)), nil
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return "", e
	}
	raw := make([]byte, 32)
	if _, e = rand.Read(raw); e != nil {
		return "", e
	}
	v := hex.EncodeToString(raw)
	if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		return "", e
	}
	if e = os.WriteFile(p, []byte(v+"\n"), 0600); e != nil {
		return "", e
	}
	return v, nil
}
func isLoopback(listen string) bool {
	h, _, _ := net.SplitHostPort(listen)
	return h == "localhost" || net.ParseIP(h).IsLoopback()
}
