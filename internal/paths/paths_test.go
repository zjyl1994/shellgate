package paths

import (
	"path/filepath"
	"testing"
)

func TestDataDirPriority(t *testing.T) {
	t.Setenv("SHELLGATE_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "/xdg")
	got, e := DataDir("/chosen")
	if e != nil || got != "/chosen" {
		t.Fatalf("got %q %v", got, e)
	}
	got, _ = DataDir("")
	if got != filepath.Join("/xdg", "shellgate") {
		t.Fatal(got)
	}
}
