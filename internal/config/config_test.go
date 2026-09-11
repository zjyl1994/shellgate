package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitAndToken(t *testing.T) {
	d := t.TempDir()
	if e := Init(d); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(d, "mcp_token"))
	if e != nil {
		t.Fatal(e)
	}
	if len(strings.TrimSpace(string(b))) != 64 {
		t.Fatal("token length")
	}
	b, e = os.ReadFile(filepath.Join(d, "mcp_log_token"))
	if e != nil || len(strings.TrimSpace(string(b))) != 64 {
		t.Fatal("log token")
	}
	if _, e = Load(d); e != nil {
		t.Fatalf("empty host registry is valid: %v", e)
	}
	r, e := Load(d)
	if e != nil {
		t.Fatal(e)
	}
	if r.Config.Audit.RecordScriptContent {
		t.Fatal("script content audit should default to disabled")
	}
}
func TestStrictYAML(t *testing.T) {
	d := t.TempDir()
	if e := Init(d); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(d, "config.yaml")
	b, _ := os.ReadFile(p)
	if e := os.WriteFile(p, append(b, []byte("\nwat: no\n")...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(d); e == nil || !strings.Contains(e.Error(), "field wat") {
		t.Fatalf("%v", e)
	}
}
