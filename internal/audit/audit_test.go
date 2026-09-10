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
	w := New(d, "{host}.jsonl", 10)
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
	w := New(t.TempDir(), "{host}.jsonl", 4)
	o := w.LimitTail([]byte("cdef"), 6)
	if o.Text != "cdef" || !o.Truncated || o.OriginalBytes != 6 || o.SavedBytes != 4 {
		t.Fatal(o)
	}
}
func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "?") == s }
