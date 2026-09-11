package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQueryLogsSearchAndCursor(t *testing.T) {
	d := t.TempDir()
	now := time.Now().In(time.Local).Truncate(time.Second)
	day := now.Format("2006-01-02")
	if err := os.MkdirAll(filepath.Join(d, day), 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(d, day, "web.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []map[string]any{
		{"ts": now.Format(time.RFC3339Nano), "event": "command", "host": "web", "command": "systemctl restart nginx"},
		{"ts": now.Add(time.Second).Format(time.RFC3339Nano), "event": "result", "host": "web", "stdout": "nginx active"},
	} {
		b, _ := json.Marshal(r)
		if _, err := f.Write(append(b, '\n')); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	q := Query{Hosts: []string{"web"}, From: now.Add(-time.Second).Format("20060102150405"), To: now.Add(2 * time.Second).Format("20060102150405"), Limit: 1, Search: &Search{Mode: "glob", Query: "systemctl*restart"}}
	first, err := QueryLogs(d, q, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Records) != 1 || first.NextCursor == "" {
		t.Fatalf("%#v", first)
	}
	q.Cursor, q.Search = first.NextCursor, nil
	second, err := QueryLogs(d, q, []byte("key"))
	if err == nil {
		t.Fatal("cursor must be bound to filters")
	}
	q.Cursor, q.Search = first.NextCursor, &Search{Mode: "glob", Query: "systemctl*restart"}
	second, err = QueryLogs(d, q, []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Records) != 0 {
		t.Fatalf("%#v", second)
	}
}

func TestResolveTimeRange(t *testing.T) {
	if _, _, err := resolveTimeRange(Query{From: "20260911120000", To: "20260911130000", TimeRange: "today"}); err == nil {
		t.Fatal("mixed time selectors should fail")
	}
	from, to, err := resolveTimeRange(Query{TimeRange: "last_1h"})
	if err != nil || to.Sub(from) != time.Hour {
		t.Fatalf("from=%v to=%v err=%v", from, to, err)
	}
}
