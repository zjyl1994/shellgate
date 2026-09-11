package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandWritesJSONL(t *testing.T) {
	d := t.TempDir()
	w := New(d, "{host}.jsonl", 10, false)
	if e := w.Command("id", "web", "echo hi"); e != nil {
		t.Fatal(e)
	}
	matches, e := filepath.Glob(filepath.Join(d, "*", "web.jsonl"))
	if e != nil || len(matches) != 1 {
		t.Fatal(matches, e)
	}
	b, e := os.ReadFile(matches[0])
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e = json.Unmarshal([]byte(strings.TrimSpace(string(b))), &v); e != nil {
		t.Fatal(e)
	}
	if v["event"] != "command" || v["request_id"] != "id" {
		t.Fatal(v)
	}
}
func TestTruncateTailUTF8(t *testing.T) {
	o := TruncateTail([]byte("甲乙丙丁"), 7)
	if !o.Truncated || !utf8Valid(o.Text) {
		t.Fatal(o)
	}
}

func TestLimitTailKeepsOriginalLength(t *testing.T) {
	w := New(t.TempDir(), "{host}.jsonl", 4, false)
	o := w.LimitTail([]byte("cdef"), 6)
	if o.Text != "cdef" || !o.Truncated || o.OriginalBytes != 6 || o.SavedBytes != 4 {
		t.Fatal(o)
	}
}
func TestScriptDefaultsToDigestOnly(t *testing.T) {
	d := t.TempDir()
	w := New(d, "{host}.jsonl", 10, false)
	if e := w.Script("id", "web", "echo secret"); e != nil {
		t.Fatal(e)
	}
	matches, _ := filepath.Glob(filepath.Join(d, "*", "web.jsonl"))
	b, e := os.ReadFile(matches[0])
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e = json.Unmarshal([]byte(strings.TrimSpace(string(b))), &v); e != nil {
		t.Fatal(e)
	}
	if v["event"] != "script" || v["script_sha256"] == "" || v["script_bytes"] != float64(len("echo secret")) {
		t.Fatal(v)
	}
	if _, ok := v["script"]; ok {
		t.Fatal("script content was recorded despite the default")
	}
}

func TestScriptCanRecordContentWhenConfigured(t *testing.T) {
	d := t.TempDir()
	w := New(d, "{host}.jsonl", 10, true)
	if e := w.Script("id", "web", "echo hello"); e != nil {
		t.Fatal(e)
	}
	matches, _ := filepath.Glob(filepath.Join(d, "*", "web.jsonl"))
	b, e := os.ReadFile(matches[0])
	if e != nil {
		t.Fatal(e)
	}
	var v map[string]any
	if e = json.Unmarshal([]byte(strings.TrimSpace(string(b))), &v); e != nil {
		t.Fatal(e)
	}
	if v["script"] != "echo hello" {
		t.Fatal(v)
	}
}
func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "?") == s }
