package broker

import (
	"context"
	"testing"

	"github.com/zjyl1994/shellgate/internal/hosts"
)

func TestExecManyReturnsAResultForEveryRequestedHost(t *testing.T) {
	b := &Broker{reg: hosts.New(nil)}
	got := b.ExecMany(context.Background(), []string{"missing-a", "missing-b"}, "true")
	if len(got.Results) != 2 {
		t.Fatalf("result count = %d, want 2", len(got.Results))
	}
	for i, want := range []string{"missing-a", "missing-b"} {
		if got.Results[i].Host != want {
			t.Errorf("result[%d].Host = %q, want %q", i, got.Results[i].Host, want)
		}
		if got.Results[i].Error != "unknown_host" {
			t.Errorf("result[%d].Error = %q, want unknown_host", i, got.Results[i].Error)
		}
	}
	if got.HostsRequested != 2 || got.HostsOK != 0 || got.HostsFailed != 2 {
		t.Errorf("summary = requested:%d ok:%d failed:%d, want 2:0:2", got.HostsRequested, got.HostsOK, got.HostsFailed)
	}
	if got.Status != "all_failed" {
		t.Errorf("status = %q, want all_failed", got.Status)
	}
	if len(got.Failed) != 2 || got.Failed[0] != "missing-a" || got.Failed[1] != "missing-b" {
		t.Errorf("failed = %#v, want requested host names", got.Failed)
	}
}

func TestSummarizeBatchStatus(t *testing.T) {
	tests := []struct {
		name        string
		results     []HostResult
		status      string
		ok, failed  int
		failedHosts []string
	}{
		{"ok", []HostResult{{Host: "a", Result: Result{OK: true}}}, "ok", 1, 0, []string{}},
		{"partial", []HostResult{{Host: "a", Result: Result{OK: true}}, {Host: "b"}}, "partial", 1, 1, []string{"b"}},
		{"all_failed", []HostResult{{Host: "a"}, {Host: "b"}}, "all_failed", 0, 2, []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := summarizeBatch(tt.results)
			if got.Status != tt.status || got.HostsRequested != len(tt.results) || got.HostsOK != tt.ok || got.HostsFailed != tt.failed {
				t.Fatalf("summary = %#v", got)
			}
			if len(got.Failed) != len(tt.failedHosts) {
				t.Fatalf("failed = %#v, want %#v", got.Failed, tt.failedHosts)
			}
			for i := range tt.failedHosts {
				if got.Failed[i] != tt.failedHosts[i] {
					t.Fatalf("failed = %#v, want %#v", got.Failed, tt.failedHosts)
				}
			}
		})
	}
}
