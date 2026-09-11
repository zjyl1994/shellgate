package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type Writer struct {
	dir, template       string
	limit               int
	recordScriptContent bool
	mu                  sync.Mutex
	now                 func() time.Time
}
type Output struct {
	Text                      string
	Truncated                 bool
	OriginalBytes, SavedBytes int
}

func New(dir, template string, limit int, recordScriptContent bool) *Writer {
	return &Writer{dir: dir, template: template, limit: limit, recordScriptContent: recordScriptContent, now: time.Now}
}
func (w *Writer) Command(id, host, command string) error {
	return w.write(host, map[string]any{"ts": w.now().Format(time.RFC3339Nano), "event": "command", "request_id": id, "host": host, "command": command})
}
func (w *Writer) Script(id, host, script string) error {
	digest := sha256.Sum256([]byte(script))
	record := map[string]any{
		"ts":            w.now().Format(time.RFC3339Nano),
		"event":         "script",
		"request_id":    id,
		"host":          host,
		"script_sha256": hex.EncodeToString(digest[:]),
		"script_bytes":  len([]byte(script)),
	}
	if w.recordScriptContent {
		record["script"] = script
	}
	return w.write(host, record)
}
func (w *Writer) Result(id, host string, exit int, d time.Duration, stdout, stderr Output) error {
	return w.write(host, map[string]any{"ts": w.now().Format(time.RFC3339Nano), "event": "result", "request_id": id, "host": host, "exit_code": exit, "duration_ms": d.Milliseconds(), "stdout": stdout.Text, "stderr": stderr.Text, "stdout_truncated": stdout.Truncated, "stderr_truncated": stderr.Truncated, "stdout_original_bytes": stdout.OriginalBytes, "stderr_original_bytes": stderr.OriginalBytes, "stdout_saved_bytes": stdout.SavedBytes, "stderr_saved_bytes": stderr.SavedBytes})
}
func (w *Writer) Error(id, host, stage, code, state string) error {
	return w.write(host, map[string]any{"ts": w.now().Format(time.RFC3339Nano), "event": "error", "request_id": id, "host": host, "stage": stage, "error": code, "remote_state": state})
}
func (w *Writer) write(host string, v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	day := w.now().Format("2006-01-02")
	dir := filepath.Join(w.dir, day)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	name := strings.ReplaceAll(w.template, "{host}", host)
	f, e := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := json.Marshal(v)
	if e == nil {
		b = append(b, '\n')
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	return e
}
func (w *Writer) Limit(b []byte) Output { return TruncateTail(b, w.limit) }
func (w *Writer) OutputLimit() int      { return w.limit }

// LimitTail records a bounded tail captured while streaming output. original
// is the total number of bytes received, including bytes discarded before b.
func (w *Writer) LimitTail(b []byte, original int) Output {
	o := TruncateTail(b, w.limit)
	if original > len(b) {
		// b may begin in the middle of a UTF-8 rune after a streaming trim.
		start := 0
		for start < len(b) && !utf8.RuneStart(b[start]) {
			start++
		}
		o.Text = string(b[start:])
		o.SavedBytes = len(b[start:])
		o.Truncated = true
	}
	o.OriginalBytes = original
	return o
}
func TruncateTail(b []byte, limit int) Output {
	o := Output{OriginalBytes: len(b)}
	if len(b) <= limit {
		o.Text = string(b)
		o.SavedBytes = len(b)
		return o
	}
	start := len(b) - limit
	for start < len(b) && !utf8.RuneStart(b[start]) {
		start++
	}
	o.Text = string(b[start:])
	o.Truncated = true
	o.SavedBytes = len(b[start:])
	return o
}
func (w *Writer) String() string { return fmt.Sprintf("audit(%s)", w.dir) }
